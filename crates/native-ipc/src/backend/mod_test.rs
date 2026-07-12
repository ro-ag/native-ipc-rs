use super::*;
use static_assertions::assert_not_impl_any;

assert_not_impl_any!(ChannelPeerReceipt: Clone);
assert_not_impl_any!(ImageIdentityReceipt: Clone);
assert_not_impl_any!(AuthenticatedPeerReceipt: Clone);
assert_not_impl_any!(AuthenticatedNativeEndpoint<()>: Clone);
assert_not_impl_any!(AuthenticatedNativeEndpoint<()>: Sync);
static_assertions::assert_impl_all!(AuthenticatedNativeEndpoint<()>: Send);

#[test]
fn endpoint_and_image_receipts_must_name_the_same_exact_child() {
    let facts = PeerFacts::new(10, 11, [7; 32], EndpointRole::Coordinator).unwrap();
    // SAFETY: this unit test models completed native verification.
    let channel = unsafe { ChannelPeerReceipt::from_verified_native(facts) };
    let wrong_facts = PeerFacts::new(10, 12, [7; 32], EndpointRole::Coordinator).unwrap();
    // SAFETY: this unit test models completed native verification.
    let wrong_image = unsafe { ImageIdentityReceipt::from_verified_native(wrong_facts) };
    assert!(matches!(
        AuthenticatedPeerReceipt::combine(channel, wrong_image),
        Err(SessionTransportError::IdentityMismatch)
    ));

    // SAFETY: this unit test models completed native verification.
    let channel = unsafe { ChannelPeerReceipt::from_verified_native(facts) };
    // SAFETY: this unit test models completed native verification.
    let image = unsafe { ImageIdentityReceipt::from_verified_native(facts) };
    let authenticated = AuthenticatedPeerReceipt::combine(channel, image).unwrap();
    // SAFETY: this unit test models a transport retaining both receipts.
    let endpoint = unsafe { AuthenticatedNativeEndpoint::from_verified_native((), authenticated) };
    assert_eq!(endpoint.peer_facts(), facts);

    assert!(PeerFacts::new(0, 11, [7; 32], EndpointRole::Coordinator).is_none());
    assert!(PeerFacts::new(10, 10, [7; 32], EndpointRole::Coordinator).is_none());
    assert!(PeerFacts::new(10, 11, [0; 32], EndpointRole::Coordinator).is_none());
}
