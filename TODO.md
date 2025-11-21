# TODO: Fix Punishments Display Based on Violations

## Tasks
- [ ] Update server.js: Change punishment addition to set max: null instead of Infinity
- [ ] Update server.js: Modify getCurrentPunishment to find the highest min <= totalBroken (assuming sorted by min)
- [ ] Update punishments.ejs: Display ranges as "X+" when max is null
- [ ] Test the changes to ensure punishments display correctly based on violation count
