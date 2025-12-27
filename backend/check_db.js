const mysql = require('mysql2');

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Meet1234@',
  database: 'lost_and_found'
});

db.connect((err) => {
  if (err) {
    console.log('Database connection failed:', err.message);
    return;
  }
  console.log('Connected to database');
  
  db.query('SELECT id, name, email, profile_picture FROM lostandfound WHERE profile_picture IS NOT NULL LIMIT 5', (err, results) => {
    if (err) {
      console.log('Query error:', err.message);
    } else {
      console.log('Users with profile pictures:');
      results.forEach(user => {
        console.log(`ID: ${user.id}, Name: ${user.name}, Email: ${user.email}, Profile Picture: ${user.profile_picture}`);
      });
    }
    db.end();
  });
});
