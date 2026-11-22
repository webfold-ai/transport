use super::{adapter::MeshAclRule, compute_diff};
use uuid::Uuid;

#[test]
fn desired_and_actual_diff_adds_missing_revokes_stale_and_preserves_the_exact_pair() {
    let rule = |user, deployment| MeshAclRule {
        user_id: Uuid::from_u128(user),
        deployment_id: Uuid::from_u128(deployment),
        deployment_name: "SYNTHETIC".into(),
        role: "member".into(),
    };
    let kept = rule(1, 10);
    let missing = rule(2, 10);
    let stale = rule(1, 20);
    let diff = compute_diff(&[kept.clone(), missing.clone()], &[kept, stale.clone()]);
    assert_eq!(diff.to_add, vec![missing]);
    assert_eq!(diff.to_remove, vec![stale]);
}
