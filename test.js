
const { TamimHardcode, encrypt, decrypt, encryptFile, decryptFile, isLicensed, getInfo } = require('./index.js');

console.log('🔐 TamimHardcode Test Suite\n');

// Test package info
console.log('📋 Package Info:', getInfo());
console.log('✅ License Status:', isLicensed() ? 'Valid' : 'Invalid');

try {
    // Test basic encryption/decryption
    console.log('\n🧪 Testing Basic Encryption/Decryption:');
    const originalText = "This is a secret message from Tamim!";
    console.log('Original:', originalText);
    
    const encrypted = encrypt(originalText);
    console.log('Encrypted:', encrypted.substring(0, 50) + '...');
    
    const decrypted = decrypt(encrypted);
    console.log('Decrypted:', decrypted);
    console.log('✅ Basic test:', originalText === decrypted ? 'PASSED' : 'FAILED');
    
    // Test with custom password
    console.log('\n🔑 Testing Custom Password:');
    const customPassword = "myCustomPassword123!";
    const encryptedCustom = encrypt("Custom password test", customPassword);
    const decryptedCustom = decrypt(encryptedCustom, customPassword);
    console.log('✅ Custom password test:', decryptedCustom === "Custom password test" ? 'PASSED' : 'FAILED');
    
    // Test class instantiation
    console.log('\n🏗️ Testing Class Instantiation:');
    const tamim = new TamimHardcode();
    const classEncrypted = tamim.encrypt("Class method test");
    const classDecrypted = tamim.decrypt(classEncrypted);
    console.log('✅ Class method test:', classDecrypted === "Class method test" ? 'PASSED' : 'FAILED');
    
    // Test error handling
    console.log('\n⚠️ Testing Error Handling:');
    try {
        decrypt("invalid_encrypted_data");
        console.log('❌ Error handling test: FAILED (should have thrown error)');
    } catch (error) {
        console.log('✅ Error handling test: PASSED');
    }
    
    console.log('\n🎉 All tests completed!');
    
} catch (error) {
    console.error('❌ Test failed:', error.message);
}
