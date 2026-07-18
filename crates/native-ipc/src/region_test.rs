use super::*;

#[test]
fn zero_id_fails_and_preparation_preserves_generic_metadata() {
    assert!(RegionId::new(0).is_none());
    let mut private = PrivateRegion::allocate(RegionOptions::fixed(37)).unwrap();
    private.initialize(|bytes| bytes[..4].copy_from_slice(b"NIPC"));
    let id = RegionId::new(9).unwrap();
    let prepared = private
        .prepare(RegionSpec {
            id,
            writer: WriterEndpoint::Receiver,
        })
        .unwrap();
    assert_eq!(prepared.spec.id, id);
    assert_eq!(prepared.spec.writer, WriterEndpoint::Receiver);
    assert_eq!(
        prepared.request.permissions().peer_access(),
        memory::MemoryAccess::ReadWrite
    );
    assert_eq!(
        prepared.guard_capability(),
        GuardCapability {
            requested: GuardPolicy::BestEffort,
            installed: false,
        }
    );
    assert!(prepared.request.mapped_len() >= 37);
}

#[test]
fn allocation_accepts_every_guard_policy_and_preparation_reports_it() {
    for policy in [
        GuardPolicy::BestEffort,
        GuardPolicy::Require,
        GuardPolicy::Disable,
    ] {
        let private =
            PrivateRegion::allocate(RegionOptions::fixed(37).with_guard_policy(policy)).unwrap();
        let prepared = private
            .prepare(RegionSpec {
                id: RegionId::new(11).unwrap(),
                writer: WriterEndpoint::Coordinator,
            })
            .unwrap();
        // Preparation never installs guard bands; installation happens when a
        // committed batch maps each endpoint's own active views.
        assert_eq!(
            prepared.guard_capability(),
            GuardCapability {
                requested: policy,
                installed: false,
            }
        );
    }
}
