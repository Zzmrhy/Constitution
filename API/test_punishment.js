const fs = require('fs');

const punishments = JSON.parse(fs.readFileSync('./API/punishments.json', 'utf8')).punishments;
const violations = JSON.parse(fs.readFileSync('./API/violations.json', 'utf8')).violations;
const totalBroken = violations.reduce((sum, v) => sum + v.brokenRules.length, 0);

console.log('Total violations:', totalBroken);
console.log('Punishments:', punishments);

function getCurrentPunishment(totalBroken) {
  if (totalBroken === 0) return null;
  // Sort punishments by min ascending
  const sortedPunishments = punishments.slice().sort((a, b) => a.min - b.min);
  // Find the punishment with the highest min <= totalBroken
  for (let i = sortedPunishments.length - 1; i >= 0; i--) {
    const p = sortedPunishments[i];
    if (totalBroken >= p.min && (p.max === null || totalBroken <= p.max)) {
      return p;
    }
  }
  return null;
}

const current = getCurrentPunishment(totalBroken);
console.log('Current punishment:', current);

// Test edge cases
console.log('Test totalBroken=0:', getCurrentPunishment(0));
console.log('Test totalBroken=3:', getCurrentPunishment(3));
console.log('Test totalBroken=5:', getCurrentPunishment(5));
console.log('Test totalBroken=6:', getCurrentPunishment(6));
console.log('Test totalBroken=10:', getCurrentPunishment(10));
