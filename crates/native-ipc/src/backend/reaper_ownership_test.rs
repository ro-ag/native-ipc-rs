use super::reaper_ownership::ReaperOwnership;

#[test]
fn concurrent_final_owner_drops_latch_reaper_termination() {
    loom::model(|| {
        let first_owner = ReaperOwnership::new();
        let termination = first_owner.termination();
        let second_owner = first_owner.clone();

        let first_drop = loom::thread::spawn(move || drop(first_owner));
        let second_drop = loom::thread::spawn(move || drop(second_owner));

        first_drop.join().expect("first owner drop panicked");
        second_drop.join().expect("second owner drop panicked");
        assert!(termination.requested());
    });
}
