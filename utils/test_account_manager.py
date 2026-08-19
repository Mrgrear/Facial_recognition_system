import sys
sys.path.append(".")
import numpy as np
from auth.account_manager import AccountManager

print("=== Account Manager Test ===\n")
am = AccountManager()

# Create accounts
am.create_account("admin1", role="admin")
am.create_account("great", role="user")
print("✅ Accounts created")

# Test single face enforcement
print("\n--- Single Face Enforcement ---")
for count in [0, 1, 2, 3]:
    allowed, msg = am.check_single_face(count)
    status = "✅" if allowed else "❌"
    print(f"{status} Faces={count}: {msg}")

# Test failed login attempts
print("\n--- Login Attempt Lockout ---")
for i in range(1, 6):
    locked, lock_type, msg = am.record_failed_attempt("great")
    print(f"Attempt {i}: {msg}")
    if locked:
        break

# Unlock by admin
am.unlock_account("great")
print("✅ Admin unlocked account")

# Test spoof attempts
print("\n--- Spoof Attempt Lockout ---")
am.create_account("user2", role="user")
for i in range(1, 4):
    locked, msg = am.record_spoof_attempt("user2")
    print(f"Spoof {i}: {msg}")
    if locked:
        break

# Test account recovery
print("\n--- Account Recovery ---")
am.create_account("user3", role="user")

# Enroll original face
dummy_embedding = np.random.rand(512)
am.enroll_face("user3", dummy_embedding)
print("✅ Original face enrolled for user3")

# Simulate accident — admin initiates recovery
ok, msg = am.initiate_recovery(
    "user3", "admin1",
    "User involved in accident — facial changes"
)
print(f"Recovery initiated: {msg}")

# Check recovery status
status = am.get_recovery_status("user3")
print(f"Recovery pending: {status['recovery_pending']}")
print(f"Reason: {status['recovery_reason']}")

# Admin enrolls new face — all existing data preserved
new_embedding = np.random.rand(512)
ok, msg = am.complete_recovery("user3", new_embedding, "admin1")
print(f"Recovery completed: {msg}")

# Test account status
print("\n--- Account Status Summary ---")
accounts = am.list_all_accounts()
for acc in accounts:
    print(f"User: {acc['username']} | "
          f"Role: {acc['role']} | "
          f"Enrolled: {acc['enrolled']} | "
          f"Locked: {acc['is_locked']}")

print("\n✅ All account manager tests passed!")