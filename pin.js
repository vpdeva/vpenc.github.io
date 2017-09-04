define(function(require) {
	var CryptoJS = require('crypto-js/core');
	var HEX = require('crypto-js/enc-hex');
	var TripleDES = require('crypto-js/tripledes');
	var Buffer = require('buffer/').Buffer;
	var xor = require('buffer-xor');
	var NodeRSA = require('node-rsa');
	var ECB = require('crypto-js/mode-ecb');
	var NoPadding = require('crypto-js/pad-nopadding');


		 function convertViewToModel(pin) {
			if (pin) {
				var pinBlock = document.getElementById("pin").value;;

				// create pin block
				if (pinBlock.length == 4) {
					pinBlock = this.getPinBlock(pinBlock);
				}

				// generate random Triple Des Key (32 bits)
				// var key1andKey2 = this.generateTripleDesKey();
				// console.log('Key1 and Key 2: ', key1andKey2);

				//Triple Des Key Algorithm (K1 | K2 | K1)
				var tripleDesK1K2 = 'F72985199E805EF2AD298385E04FCE68';
				var tripleDesKey1 = tripleDesK1K2.substring(0, 16);
				var k1k2tripleDesKey = new Buffer(tripleDesK1K2, 'hex');
				var k1k2k1tripleDesKey = HEX.parse(tripleDesK1K2 + tripleDesKey1);
				console.log('TripleDesKeyHex: ' + tripleDesK1K2 + tripleDesKey1);

				// encrypt pin block with Triple Des Key
				var encryptedPinBlock = CryptoJS.TripleDES.encrypt(
					pinBlock,
					k1k2k1tripleDesKey,
					{
						mode: CryptoJS.mode.ECB,
						padding: CryptoJS.pad.NoPadding,
					}
				);
				var encPinBlock = encryptedPinBlock.ciphertext.toString().toUpperCase();
				document.getElementById("encrypted").innerHTML = encPinBlock;
				console.log('Encrypted Pin Block (Triple Des): ' + encPinBlock);

				// encrypt Triple Des Key
				var encryptedTripleDesKey = this.encryptTripleDesKey(k1k2tripleDesKey);
				return encryptedTripleDesKey.toString();
			}
			return;
		}

		 function getPinBlock(pin) {
			// creating pin and tan hex block (string)
			var pinBlock = '04' + pin + 'FFFFFFFFFF';
			var tan = this.getOption('tan');
			var tanBlock = '0000' + tan.slice(0, -1).substring(3);
			console.log('Pin: ' + pin);
			console.log('Tan: ' + tan);

			// convert to Hex
			pinBlock = new Buffer(pinBlock, 'hex');
			tanBlock = new Buffer(tanBlock, 'hex');

			var xorBlock = xor(pinBlock, tanBlock);
			console.log('pinBlock in Hex: ' + xorBlock.toString('hex'));
			return HEX.parse(xorBlock.toString('hex'));
		}

		 function getPinFromBlock(xorBlock) {
			xorBlock = new Buffer(xorBlock, 'hex');
			var psuedoPinBlock = document.getElementById("tan").value;
			psuedoPinBlock = new Buffer('0000' + psuedoPinBlock.substr(4), 'hex');
			var pinBlock = xor(xorBlock, psuedoPinBlock);
			pinBlock = pinBlock.toString('hex');
			return pinBlock.substr(2, 4);
		}

		 function generateTripleDesKey() {
			var tripleDesKey = CryptoJS.lib.WordArray.random(64 / 8);
			console.log('Triple Des Key (Hex string): ' + tripleDesKey);
			return HEX.parse(tripleDesKey);
		}

		 function encryptTripleDesKey(tripleDesKey) {
			//Encrypt Triple Des Key using public key
			var publicKey = document.getElementById("publickey").value;
			var key = NodeRSA();
			var keyBuffer = new Buffer(publicKey, 'hex');
			key.importKey(keyBuffer, 'pkcs1-public-der');
			key.setOptions({ encryptionScheme: 'pkcs1' });
			var encrypted = key.encrypt(tripleDesKey, 'hex');
			var encrypted3deskey = encrypted.toUpperCase();
			document.getElementById("3Des").value = encrypted3deskey;
			console.log('Encrypted 3DES Key: ', encrypted3deskey);

			return encrypted;
		}
	})
