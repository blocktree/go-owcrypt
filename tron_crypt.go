package owcrypt
import "math/big"

	func tron_hmac_rfc6979_init(key[]byte,keylen int)([]byte, int){
		k := make([]byte,32)
		v := make([]byte,32)
		out :=make([]byte,64)
		tempbuf := make([]byte,33+keylen)
		//step b in RFC6979
		//copy(v,0x01,32)
		for i:=0;i<32;i++{
			v[i]=0x1
		} 
		//step c in RFC6979
		for i:=0;i<32;i++{
			k[i]=0x0
		} 
		//step d in RFC6979
		copy(tempbuf[:32],v[:])
		tempbuf[32]=0;
		copy(tempbuf[33:33+keylen],key[:])
		k=Hmac(k,tempbuf,HMAC_SHA256_ALG)
	   
		//step e in RFC6979
		v=Hmac(k,v,HMAC_SHA256_ALG)
		//step f in RFC6979
		copy(tempbuf[:32],v[:])
		tempbuf[32]=0x01;
		k=Hmac(k,tempbuf,HMAC_SHA256_ALG)
		//step g in RFC6979
		v=Hmac(k,v,HMAC_SHA256_ALG)
		retry := 0
		copy(out[:32],k[:])
		copy(out[32:64],v[:])
		//返回k||v,retry
		return out,retry
	}
	/*
	@brife: according to RFC6979 standard
	@paramter[in]k pointer to k generates in HMAC_RFC6979_init()
	@paramter[in]v ipointer to v generates in HMAC_RFC6979_init()
	@paramter[in]retry denotes the retry in HMAC_RFC6979_init()
	@paramter[out]the first return value pointer to nounce(type is []byte)
	@paramter[out]the second return value is retry(type is int)
	*/
	func tron_hmac_rfc6979_gnerate(k, v []byte,retry,nouncelen int)([]byte,int){
		 nounce :=make([]byte,nouncelen)
		  j := 0
		 if retry==1{
			 tempbuf :=make([]byte,33)
			 copy(tempbuf[:32],v[:])
			 //memset(tempbuf,0,1)
			 tempbuf[32]=0;
			 k=Hmac(k,tempbuf,HMAC_SHA256_ALG)
			 v=Hmac(k,v,HMAC_SHA256_ALG)
		 }
		 for i:=0;i<nouncelen;i+=32{
			v=Hmac(k[:],v[:],HMAC_SHA256_ALG)
			copy(nounce[(j*32):((j+1)*32)],v[:])
			j++
		 }
		 retry=1
		 return nounce,retry
	}
	
	
	func tron_nonce_function_rfc6979(msg,key,algo,extradata[]byte,counter uint32)[]byte{
		keydata :=make([]byte,112)
		nounce :=make([]byte,(counter+1)*32)
		copy(keydata[:32],key[:])
		copy(keydata[32:64],msg[:])
		keylen := 64
		if extradata != nil{
			copy(keydata[64:96],extradata[:])
			keylen +=32
		}
		if algo != nil{
			copy(keydata[keylen:keylen+16],algo[:])
		}
		ret,retry:=tron_hmac_rfc6979_init(keydata,keylen)
		
		for i:=uint32(0);i<=counter;i++{
			ReTry:=retry
			temp,retry := tron_hmac_rfc6979_gnerate(ret[:32], ret[32:],ReTry,32)
			copy(nounce[i*32:(i+1)*32],temp[:])
			ReTry=retry
		}
		
		return nounce
		
	}
	
	func tron_set_uint64(a[]byte)[]uint64{
		b:=make([]uint64,len(a)>>3)
		b[0]=(uint64(a[0])<<56) |(uint64 (a[1])<<48) |(uint64(a[2])<<40) |(uint64(a[3])<<32) |(uint64(a[4])<<24) |(uint64(a[5])<<16)|(uint64(a[6])<<8)|(uint64(a[7]))
		b[1]=(uint64(a[8])<<56) |(uint64(a[9])<<48) |(uint64(a[10])<<40) |(uint64(a[11])<<32) |(uint64(a[12])<<24) |(uint64(a[13])<<16)|(uint64(a[14])<<8)|(uint64(a[15]))
		b[2]=(uint64(a[16])<<56) |(uint64(a[17])<<48) |(uint64(a[18])<<40) |(uint64(a[19])<<32) |(uint64(a[20])<<24) |(uint64(a[21])<<16)|(uint64(a[22])<<8)|(uint64(a[23]))
		b[3]=(uint64(a[24])<<56) |(uint64(a[25])<<48) |(uint64(a[26])<<40) |(uint64(a[27])<<32) |(uint64(a[28])<<24) |(uint64(a[29])<<16)|(uint64(a[30])<<8)|(uint64(a[31]))
		return b
	}
	
	func tron_set_uint32(a[]byte)[]uint32{
		b:=make([]uint32,len(a)>>2)
		b[0]=(uint32(a[0])<<24)|(uint32(a[1])<<16)|(uint32(a[2])<<8)|(uint32(a[3]))
		b[1]=(uint32(a[4])<<24)|(uint32(a[5])<<16)|(uint32(a[6])<<8)|(uint32(a[7]))
		b[2]=(uint32(a[8])<<24)|(uint32(a[9])<<16)|(uint32(a[10])<<8)|(uint32(a[11]))
		b[3]=(uint32(a[12])<<24)|(uint32(a[13])<<16)|(uint32(a[14])<<8)|(uint32(a[15]))
		b[4]=(uint32(a[16])<<24)|(uint32(a[17])<<16)|(uint32(a[18])<<8)|(uint32(a[19]))
		b[5]=(uint32(a[20])<<24)|(uint32(a[21])<<16)|(uint32(a[22])<<8)|(uint32(a[23]))
		b[6]=(uint32(a[24])<<24)|(uint32(a[25])<<16)|(uint32(a[26])<<8)|(uint32(a[27]))
		b[7]=(uint32(a[28])<<24)|(uint32(a[29])<<16)|(uint32(a[30])<<8)|(uint32(a[31]))
		return b
	}
	
	func tron_check_overflow_uint64(a[]byte)bool{
		var yes bool
		var no bool
		yes=false
		no=false
		curveOrder := GetCurveOrder(ECC_CURVE_SECP256K1)
		a_uint64:=tron_set_uint64(a)
		curveOrder_uint64:=tron_set_uint64(curveOrder)
		no =no||(a_uint64[0]<curveOrder_uint64[0])/*no need check for a > check*/
		no =no||(a_uint64[1]<curveOrder_uint64[1])
		yes=yes||(a_uint64[1]>curveOrder_uint64[1])&&(!no)
		no=no||(a_uint64[2]<curveOrder_uint64[2])
		yes=yes||(a_uint64[2]>curveOrder_uint64[2])&&(!no)
		yes=yes||(a_uint64[3]>=curveOrder_uint64[3])&&(!no)
		return yes
	}
	
	func tron_check_overflow_uint32(a[]byte)bool{
		var yes bool
		var no bool
		yes=false
		no=false
		curveOrder := GetCurveOrder(ECC_CURVE_SECP256K1)
		a_uint32:=tron_set_uint32(a)
		curveOrder_uint32:=tron_set_uint32(curveOrder)
		no=no||(a_uint32[0] < curveOrder_uint32[0])/*no need check for a > check.*/
		no=no||(a_uint32[1]<curveOrder_uint32[1])/*no need check for a check. */
		no=no||(a_uint32[2]<curveOrder_uint32[2])/*no need check for a check.*/
		no=no||(a_uint32[3]<curveOrder_uint32[3])
		yes=yes||(a_uint32[3]>curveOrder_uint32[3])&&(!no)
		no=no||(a_uint32[4]<curveOrder_uint32[4])&&(!yes)
		yes=yes||(a_uint32[4]>curveOrder_uint32[4])&&(!no)
		no=no||(a_uint32[5]<curveOrder_uint32[5])&&(!yes)
		yes=yes||(a_uint32[5]>curveOrder_uint32[5])&&(!no)
		no=no||(a_uint32[6]<curveOrder_uint32[6])&&(!yes)
		yes=yes||(a_uint32[6]>curveOrder_uint32[6])&&(!no)
		yes=yes||(a_uint32[7]>=curveOrder_uint32[7])&&(!no)
	
		return yes
	}
	
	func tron_check_is_zero(a[]byte)bool{
		b:=make([]uint64,len(a)>>3)
		b=tron_set_uint64(a)
		return ((b[3]==0)&&(b[2]==0)&&(b[1]==0)&&(b[0]==0))
	}
	
	func tron_signatureInner(prikey[]byte,hash[]byte,nounce[]byte)([]byte, uint16){
		   var recid byte
		   signature :=make([]byte,65)
		   ret:=PreprocessRandomNum(nounce)
	
			if ret != SUCCESS{
				return nil,ret
			}
	
			//外部传入随机数，外部已经计算哈希值
			sig,ret:=Signature(prikey, nil, 0 , hash, 32, ECC_CURVE_SECP256K1 | NOUNCE_OUTSIDE_FLAG)
			if ret!=SUCCESS{
				return nil,ret
			}
			//判断[nounce]G(G is base point) Y-coordinate 的奇偶性,如果为奇数，recid=0x0;如果为奇数，recid=0x01.
			//这里应该添加判断（签名值r>order,发生的概率接近于1/2^127，几乎为0.这里不再判断，因为底层的C库输出的签名值r已经对order求模数，排除了这种情况）
			yPoint, ret1 :=GenPubkey(nounce, ECC_CURVE_SECP256K1)
			if ret1 != SUCCESS{
				return nil,ret1
			}
			if yPoint[63]%2 ==1 {
				recid |=0x01	
			}else{
				recid |=0x00
			}
			curveOrder := new(big.Int).SetBytes(GetCurveOrder(ECC_CURVE_SECP256K1))
			halfcurveorder :=big.NewInt(0)
			s := new(big.Int).SetBytes(sig[32:64])
			divider :=big.NewInt(2)
			halfcurveorder.Div(curveOrder,divider)
			sign :=s.Cmp(halfcurveorder)
			if sign > 0{
			  s.Sub(curveOrder,s)
			  sByte:=s.Bytes()
		      if len(sByte) < 32{
			     for i:=0;i<32-len(sByte);i++{
				     sByte = append([]byte{0x00}, sByte...)
			  }
		  }
		      copy(sig[32:64],sByte)
			  recid ^=1
			}
			copy(signature[:64],sig[:])
			signature[64]=recid
			return signature,ret
	}
/*
@brife: according to RFC6979 standard
@function: init HMAC
@paramter[in]key pointer to private key ||hash(message) in signature procedure
@paramter[in]keylen is the byte length of key
@paramter[out]the first return value pointer to k||v(type is []byte)
@paramter[out]the second return value is retry(type is int)
*/



/*
@function:ETH signature(ECDSA&&secp256k1)
@paramter[in]prikey pointer to private key
@paramter[in]hash pointer to the hash of message(Transaction txt)
@parameter[out]the first part is signature(r||s||v,total 65 byte);
the second part
*/
func Tron_signature(prikey[]byte,hash[]byte)([]byte, uint16){
	signature :=make([]byte,65)
	//	var recid byte
	var ret uint16
	var counter uint32
	counter=0
	if len(hash) != 32{
		return nil, FAILURE
	}
     prikey_overflow:=tron_check_overflow_uint64(prikey)
	 prikey_IsZero:=tron_check_is_zero(prikey)
	 if !prikey_overflow && !prikey_IsZero{
	  for;;{
		nounce :=tron_nonce_function_rfc6979(hash,prikey,nil,nil,counter)
		nounce_overflow:=tron_check_overflow_uint32(nounce)
		nounce_IsZero:=tron_check_is_zero(nounce)
		if!nounce_overflow && !nounce_IsZero{
			signature,ret=tron_signatureInner(prikey,hash,nounce)
			if ret==SUCCESS{
				break
			}
		}
		counter++
	  }
	 }
	
	return signature,ret
}
