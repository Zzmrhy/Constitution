# TODO List for Constitution App Updates

## 1. Create suggestions.json
- Create API/suggestions.json with initial empty array.

## 2. Update server.js for captcha modal
- Modify /api/signin: After successful signin for email 'CMP_BeHedderman@students.ects.org', set a session flag or redirect to show captcha modal instead of granting full access.

## 3. Implement suggestions backend in server.js
- Add /api/suggestions routes:
  - GET: Fetch all suggestions.
  - POST: Add new suggestion (only regular users and sub-admins; admins cannot suggest).
  - POST /api/suggestions/:id/vote: Vote on suggestion (only admins and sub-admins; sub-admin cannot vote on their own suggestion; regular users cannot vote).
- Track votes: Store approve/reject lists with user emails.
- Auto-process: If approve > reject, add suggestion text to rules.json; if reject > approve, remove suggestion.

## 4. Update views/layout.ejs
- Add captcha modal HTML and JS logic to show modal on signin for specific email.

## 5. Update views/suggestions.ejs
- Add form for submitting suggestions (visible to regular users and sub-admins).
- Display suggestions with vote counts, who voted what.
- Voting buttons only for admins and sub-admins (with restrictions).

## 6. Improve violations page CSS
- Add dedicated styles to API/public/css/index.css for better form, list, and overall styling on violations page.

## 7. Git setup and push
- Check if git initialized; if not, init.
- Add remote origin: https://github.com/Zzmrhy/Constitution.git
- Commit all changes.
- Push to origin.
