# Task: Fix Suggestions and Violations Page Issues

## Issues Identified
1. Suggestion submission form is correctly hidden for admins, but voting buttons need to be visible for admins, sub-admins, and the user who submitted the suggestion.
2. Violations page looks bland and too close; needs better spacing with increased padding and margins.

## Plan
1. Update `views/suggestions.ejs`: Modify the condition for voting buttons to include the submitter of the suggestion.
2. Update `views/violations.ejs`: Increase padding and margins for better visual spacing.
3. Test the changes to ensure UI reflects the requirements (note: API may restrict voting to admins/sub-admins only).

## Steps
- [ ] Edit `views/suggestions.ejs` to change voting button visibility condition.
- [ ] Edit `views/violations.ejs` to add more spacing (padding and margins).
- [ ] Verify changes in browser or via testing.
