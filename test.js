const LibIOP = require('./index.js');

function runTest() {
  const iop = new LibIOP();
  try {
    // Generate a new proof
    iop.generateProof();

    // Verify the proof
    const isValid = iop.verifyProof();

    if (isValid) {
      console.log('✅ Proof is valid!');
    } else {
      console.log('❌ Proof is NOT valid!');
    }
  } catch (error) {
    console.error('An error occurred:', error);
  } finally {
    // Clean up the memory used by the proof
    iop.freeProof();
  }
}

runTest();