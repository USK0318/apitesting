const mongoose = require('mongoose');

const uri= 'mongodb+srv://uppalapatisaikiran27:20A25B0318@scutiarts.rifwbjg.mongodb.net/?retryWrites=true&w=majority&appName=scutiarts'
async function run() {
  try {
    console.log('Attempting to connect to MongoDB Atlas...');
    await mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });
    console.log('Successfully connected to MongoDB Atlas');
  } catch (err) {
    console.error('Error connecting to MongoDB Atlas:', err);
  }
}  

run().catch(console.dir);

module.exports = mongoose;
