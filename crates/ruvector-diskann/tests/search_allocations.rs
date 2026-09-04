use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use ruvector_diskann::{DiskAnnConfig, DiskAnnIndex};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct CountingAllocator;

static TRACKING: AtomicBool = AtomicBool::new(false);
static LARGE_ALLOCATION_THRESHOLD: AtomicUsize = AtomicUsize::new(usize::MAX);
static LARGE_ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);
static TOTAL_ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACKING.load(Ordering::Relaxed) {
            TOTAL_ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            if layout.size() >= LARGE_ALLOCATION_THRESHOLD.load(Ordering::Relaxed) {
                LARGE_ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            }
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if TRACKING.load(Ordering::Relaxed) {
            TOTAL_ALLOCATED_BYTES.fetch_add(new_size, Ordering::Relaxed);
            if new_size >= LARGE_ALLOCATION_THRESHOLD.load(Ordering::Relaxed) {
                LARGE_ALLOCATED_BYTES.fetch_add(new_size, Ordering::Relaxed);
            }
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn pooled_search_does_not_allocate_visited_set_storage() {
    const N: usize = 250_000;
    const DIM: usize = 8;
    const SEARCHES: usize = 100;
    // Upper bound on everything the hot searches allocate: the two search
    // heaps, the re-rank buffer, and the k result strings. The graph is built
    // from `thread_rng`, so the traversal, and with it how far the heaps grow,
    // differs from run to run: measured 232,700 to 284,100 bytes over five
    // local runs and 386,400 on a CI run, all for the same code, against a
    // previous cap of 300,000 that sat inside that spread. The regression this
    // guards (a fresh VisitedSet per search) costs N * 8 bytes per search, i.e.
    // 200,000,000 here, two hundred times this bound, so the bound stays a
    // coarse sanity check rather than a tuned figure.
    const MAX_HOT_SEARCH_ALLOCATED_BYTES: usize = 1_000_000;

    let mut rng = StdRng::seed_from_u64(0x677A_110C);
    let mut index = DiskAnnIndex::new(DiskAnnConfig {
        dim: DIM,
        max_degree: 4,
        build_beam: 8,
        search_beam: 32,
        alpha: 1.0,
        ..Default::default()
    });
    for id in 0..N {
        let vector = (0..DIM).map(|_| rng.gen()).collect();
        index.insert(id.to_string(), vector).unwrap();
    }
    index.build().unwrap();

    let query: Vec<f32> = (0..DIM).map(|_| rng.gen()).collect();
    index.search(&query, 10).unwrap();

    // VisitedSet's generation vector alone requests N * sizeof(u64) bytes.
    // Count every allocation at least that large while allowing the unrelated,
    // much smaller candidate and result buffers used by the search itself.
    let visited_generation_bytes = N * std::mem::size_of::<u64>();
    LARGE_ALLOCATION_THRESHOLD.store(visited_generation_bytes, Ordering::Relaxed);
    LARGE_ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    TOTAL_ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    TRACKING.store(true, Ordering::Relaxed);
    for _ in 0..SEARCHES {
        std::hint::black_box(index.search(&query, 10).unwrap());
    }
    TRACKING.store(false, Ordering::Relaxed);

    let allocated = LARGE_ALLOCATED_BYTES.load(Ordering::Relaxed);
    let total_allocated = TOTAL_ALLOCATED_BYTES.load(Ordering::Relaxed);
    assert_eq!(
        allocated, 0,
        "{SEARCHES} hot searches allocated {allocated} bytes in visited-set-sized blocks"
    );
    assert!(
        total_allocated < MAX_HOT_SEARCH_ALLOCATED_BYTES,
        "{SEARCHES} hot searches allocated {total_allocated} total bytes, expected less than {MAX_HOT_SEARCH_ALLOCATED_BYTES} bytes and far below the {visited_generation_bytes}-byte generation array"
    );
}
