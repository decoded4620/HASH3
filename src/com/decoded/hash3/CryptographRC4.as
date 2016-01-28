package com.decoded.hash3
{
    public class CryptographRC4 {
        
        public function CryptographRC4() {}
        
        private static const _hexValues:Array                                   = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"];
        private static const sbox:Array                                           = new Array(255);
        private static const mykey:Array                                          = new Array(255);
        
        // initialize functions variables
        private static var _a:int                                               = 0;
        private static var _b:int                                               = 0;
        private static var _t:int                                               = 0;
        private static var _pLen:int                                            = 0;
        
        // calculate function variables
        private static var _cipher:Array                                        = [];
        private static var _calcI:Number                                        = 0;
        private static var _calcJ:Number                                        = 0;
        private static var _calcK:Number                                        = 0;
        private static var _calcA:Number                                        = 0;
        private static var _calcTemp:Number                                     = 0;
        private static var _calcCipherBy:Number                                 = 0;
        private static var _calcPTextLen:Number                                 = 0;
        
        // charsToHex function variables
        private static var _charsToHexResult:String;
        private static var _currCharToHexCode:int                               = 0;
        private static var _charsLen:int                                        = 0;
        private static var _charsI:int                                          = 0;
        
        // hexToChars function variables
        private static var _hexToCharCodes:Array                                = [];
        private static var _hexCodesLen:int                                     = 0;
        private static var _hexI:int                                            = 0;
        private static var _lastHexToChars:String;
        private static var _lastHexToCharsResult:Array;
        
        // charsToStr function variables
        private static var _charsToStrResult:String;
        private static var _charsToStrLen:int                                   = 0;
        private static var _charsToStrI:Number                                  = 0;
        
        // strToChars function variables. Note we switch between these arrays on 
        // alternating calls to 'strToChar' so we can call it twice (i.e. in encrypt) and still use a cached
        // array without creating / constructing new ones.
        private static var _strToCharCodes:Array                                = [];
        private static var _strToCharCodes2:Array                               = [];
        private static var _strToCharsSwapList:Boolean = false;
        private static var _lastStrToChars:String;
        private static var _lastStrToCharsResult:Array;
        
        private static var _strLen:int                                          = 0;
        private static var _strToCharsI:Number                                  = 0;
        
        /**
         * Encrypts a string with the specified key.
         */
        public static function encrypt(src:String, key:String):String {
            var chars:Array = calculate(strToChars(src), strToChars(key));
            _charsToHexResult = "";
            _charsLen = chars.length;
            
            for (_charsI = 0; _charsI < _charsLen; _charsI++) {
                _currCharToHexCode = chars[_charsI];
                _charsToHexResult += _hexValues[_currCharToHexCode >> 4] + _hexValues[_currCharToHexCode & 0xf];
            }
            
            return _charsToHexResult;
        }
        
        /**
         * Decrypts a string with the specified key.
         */
        public static function decrypt(src:String, key:String):String {
            var chars:Array = calculate(hexToChars(src), strToChars(key));
            _charsToStrResult = "";
            _charsToStrLen = chars.length;
            
            for (_charsToStrI = 0; _charsToStrI<_charsToStrLen; _charsToStrI++) {
                _charsToStrResult += String.fromCharCode(chars[_charsToStrI]);
            }
            
            return _charsToStrResult;
        }
       
        
        private static function calculate(plaintxt:Array, psw:Array):Array {
            _b = 0;
            _pLen = psw.length;
            
            for (_a = 0; _a <= 255; _a++) {
                mykey[_a] = psw[(_a%_pLen)];
                sbox[_a] = _a;
            }
            
            for (_a=0; _a<=255; _a++) {
                _b = (_b+sbox[_a]+mykey[_a]) % 256;
                _t = sbox[_a];
                sbox[_a] = sbox[_b];
                sbox[_b] = _t;
            }
            
            //truncate
            _cipher.length  = 0;
            _calcI          = 0;
            _calcJ          = 0;
            _calcK          = 0;
            _calcTemp       = 0;
            _calcCipherBy   = 0;
            _calcPTextLen   = plaintxt.length;
            
            for (_calcA = 0; _calcA<_calcPTextLen; _calcA++) {
                _calcI = (_calcI+1) % 256;
                _calcJ = (_calcJ+sbox[_calcI])%256;
                _calcTemp = sbox[_calcI];
                sbox[_calcI] = sbox[_calcJ];
                sbox[_calcJ] = _calcTemp;
                _calcK = sbox[(sbox[_calcI]+sbox[_calcJ]) % 256];
                _calcCipherBy = plaintxt[_calcA]^_calcK;
                _cipher.push(_calcCipherBy);
            }

            return _cipher;
        }
        
        private static const HEX_PREFIX:String = "0x";
        
        private static function hexToChars(hex:String):Array {
            
            // optimize repeat calls by returning previous results
            if(hex == _lastHexToChars)  { return _lastHexToCharsResult; }
            
            _lastHexToChars = hex;
            // truncate for next translation
            _hexToCharCodes.length = 0;
            var _hexCodesLen:int = hex.length;
            
            for (_hexI = (hex.substr(0, 2) == HEX_PREFIX) ? 2 : 0; _hexI<_hexCodesLen; _hexI+=2) 
            {
                _hexToCharCodes.push(parseInt(hex.substr(_hexI, 2), 16));
            }
            
            _lastHexToCharsResult = _hexToCharCodes;
            
            return _hexToCharCodes;
        }
        
        private static function strToChars(str:String):Array {
            
            if(str == _lastStrToChars){  return _lastStrToCharsResult; }
            
            _lastStrToChars = str;

            _strToCharsSwapList = !_strToCharsSwapList;
            _strLen = str.length;
            
            if(!_strToCharsSwapList)
            {
                _strToCharCodes.length = 0;
                for (_strToCharsI = 0; _strToCharsI< _strLen; _strToCharsI++) 
                {
                    _strToCharCodes.push(str.charCodeAt(_strToCharsI));
                }
                
                _lastStrToCharsResult = _strToCharCodes;
                return _strToCharCodes;
            }
            else
            {
                _strToCharCodes2.length = 0;
                for (_strToCharsI = 0; _strToCharsI< _strLen; _strToCharsI++) 
                {
                    _strToCharCodes2.push(str.charCodeAt(_strToCharsI));
                }
                
                _lastStrToCharsResult = _strToCharCodes2;
                return _strToCharCodes2;
            }
        }
        
    }
}