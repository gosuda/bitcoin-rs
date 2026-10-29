use core::cell::Cell;

thread_local! {
    static INSTALLED: Cell<usize> = const { Cell::new(0) };
    static CLOSED: Cell<usize> = const { Cell::new(0) };
}

pub(crate) fn note_installed() {
    INSTALLED.with(|count| count.set(count.get() + 1));
}

pub(crate) fn note_closed() {
    CLOSED.with(|count| count.set(count.get() + 1));
}

pub(crate) fn installed_total() -> usize {
    INSTALLED.with(Cell::get)
}

pub(crate) fn closed_total() -> usize {
    CLOSED.with(Cell::get)
}
