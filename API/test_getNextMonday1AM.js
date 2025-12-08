// Test script for getNextMonday1AM function
function getNextMonday1AM(timestamp) {
    const date = new Date(timestamp);
    const dayOfWeek = date.getDay(); // 0=Sunday, 1=Monday, ..., 6=Saturday
    let daysUntilMonday = (1 - dayOfWeek + 7) % 7;
    if (daysUntilMonday === 0 && date.getHours() < 1) {
        // If it's Monday before 1 AM, next is today at 1 AM
        daysUntilMonday = 0;
    } else if (daysUntilMonday === 0) {
        // If it's Monday after 1 AM, next is next Monday
        daysUntilMonday = 7;
    }
    date.setDate(date.getDate() + daysUntilMonday);
    date.setHours(1, 0, 0, 0);
    return date;
}

// Test cases
console.log('Testing getNextMonday1AM function:');
console.log('Current time:', new Date().toISOString());
const nextFromNow = getNextMonday1AM(Date.now());
console.log('Next Monday 1 AM from now:', nextFromNow.toISOString());

// Test on a Monday before 1 AM (simulate)
const mondayBefore1AM = new Date();
mondayBefore1AM.setDate(mondayBefore1AM.getDate() + (1 - mondayBefore1AM.getDay() + 7) % 7); // Set to next Monday
mondayBefore1AM.setHours(0, 0, 0, 0); // Midnight Monday
console.log('Simulated Monday before 1 AM:', mondayBefore1AM.toISOString());
const nextFromBefore = getNextMonday1AM(mondayBefore1AM);
console.log('Next from Monday before 1 AM:', nextFromBefore.toISOString());

// Test on Monday after 1 AM (simulate)
const mondayAfter1AM = new Date(mondayBefore1AM);
mondayAfter1AM.setHours(2, 0, 0, 0); // 2 AM Monday
console.log('Simulated Monday after 1 AM:', mondayAfter1AM.toISOString());
const nextFromAfter = getNextMonday1AM(mondayAfter1AM);
console.log('Next from Monday after 1 AM:', nextFromAfter.toISOString());

// Verify times are 1 AM
console.log('All next times should be at 1:00:00 AM:');
console.log('From now - hours:', nextFromNow.getHours());
console.log('From before - hours:', nextFromBefore.getHours());
console.log('From after - hours:', nextFromAfter.getHours());
