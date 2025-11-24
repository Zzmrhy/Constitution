# Task: Fix admin controls visibility and punishment editing/removal issues

## Summary of issues addressed
- Admin controls on the rules page were appearing incorrectly for head admin users.
- No way to remove or edit punishments for head admin due to inconsistent property usage in punishments.ejs.
- punishments.ejs had errors caused by mixed usage of `punishment.punishment` and `punishment.text`.
- Backend routes for punishment edit/remove exist but frontend inconsistencies caused issues.

## Changes made
1. **views/punishments.ejs**
   - Unified usage of punishment text property to `punishment.text`.
   - Fixed form input fields for editing punishments to use `punishment.text`.
   - Added safeguards for missing punishment text display.

2. **views/rules.ejs**
   - Adjusted admin controls visibility conditions:
     - Show admin controls (adding rules) only if `isAdmin` is true.
     - Show delete buttons only if `isAdmin` is true (head admins no longer see).
   - Suggestion form shown if user is neither admin nor head admin.

3. **views/layout.ejs**
   - Verified proper propagation of user info.
   - No changes required here.

## Next steps / Testing
- Test rules page as admin, head admin, and regular user to verify admin controls and delete buttons visibility.
- Test punishments page as head admin to confirm:
  - Edit and remove buttons appear.
  - Editing a punishment updates the data.
  - Removing a punishment deletes it successfully.
- Check for any errors in the console or UI related to punishments display.
- Confirm regular users and sub-admins have appropriate access restrictions.

## Notes
- Backend routes for head admin punishment management are confirmed present and check authorization.
- Further UX improvements can be considered for better feedback during editing/removal operations.

-----
Task fix done.
