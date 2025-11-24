# Task: Change suggestion approval flow to go through pending approvals queue

- [ ] Update `POST /api/suggestions/:id/vote` in API/server.js:
  - On majority approval, move suggestion to `pendingApprovals` with type 'rule'
  - Remove from `suggestions` list
  - Save `suggestions.json` and `pending_approvals.json`

- [ ] Update `POST /api/punishment-suggestions/:id/vote` in API/server.js:
  - On majority approval, move suggestion to `pendingApprovals` with type 'punishment'
  - Remove from `punishmentSuggestions` list
  - Save `punishment_suggestions.json` and `pending_approvals.json`

- [ ] Confirm head admin approval endpoint works unchanged to accept/reject pending approvals

- [ ] Test full voting and approval flow for rules and punishments
