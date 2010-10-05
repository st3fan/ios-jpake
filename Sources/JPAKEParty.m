// JPAKEParty.m

#import "JPAKEParty.h"

static NSString* BIGNUM2NSString(BIGNUM* bn)
{
	NSString* result = nil;

	const char* s = BN_bn2hex(bn);
	if (s != nil) {
		result = [NSString stringWithCString: s encoding: NSASCIIStringEncoding];
		OPENSSL_free((void*) s);
	}
	
	return result;
}

static void NSString2BIGNUM(NSString* s, BIGNUM** bn)
{
	BN_hex2bn(bn, [s cStringUsingEncoding: NSASCIIStringEncoding]);
}

@implementation JPAKEParty

+ (id) partyWithPassword: (NSString*) password signerIdentity: (NSString*) signerIdentity peerIdentity: (NSString*) peerIdentity
{
	return [[[self alloc] initWithPassword: password signerIdentity: signerIdentity peerIdentity: peerIdentity] autorelease];
}

- (id) initWithPassword: (NSString*) password signerIdentity: (NSString*) signerIdentity peerIdentity: (NSString*) peerIdentity
{
	if ((self = [super init]) != nil)
	{
		_signerIdentity = [signerIdentity retain];
	
		BIGNUM* p = NULL;
		BIGNUM* g = NULL;
		BIGNUM* q = NULL;

		BN_hex2bn(&p, "F9E5B365665EA7A05A9C534502780FEE6F1AB5BD4F49947FD036DBD7E905269AF46EF28B0FC07487EE4F5D20FB3C0AF8E700F3A2FA3414970CBED44FEDFF80CE78D800F184BB82435D137AADA2C6C16523247930A63B85661D1FC817A51ACD96168E95898A1F83A79FFB529368AA7833ABD1B0C3AEDDB14D2E1A2F71D99F763F");
		g = BN_new();
		BN_set_word(g, 2);
		q = BN_new();
		BN_rshift1(q, p);

		BIGNUM* secret = NULL;
		BN_asc2bn(&secret, [password cStringUsingEncoding: NSASCIIStringEncoding]);
	
		_ctx = JPAKE_CTX_new(
			[signerIdentity cStringUsingEncoding: NSASCIIStringEncoding],
			[peerIdentity cStringUsingEncoding: NSASCIIStringEncoding],
			p, g, q, secret
		);
		
		BN_free(secret);
		
		BN_free(q);
		BN_free(g);
		BN_free(p);		
	}
	return self;
}

- (void) dealloc
{
	[_signerIdentity release];
	[super dealloc];
}

#pragma mark -

- (NSDictionary*) generateMessageOne
{
	JPAKE_STEP1 step1;
	JPAKE_STEP1_init(&step1);

	JPAKE_STEP1_generate(&step1, _ctx);
	
	NSDictionary* zkp1 = [NSDictionary dictionaryWithObjectsAndKeys:
		BIGNUM2NSString(step1.p1.zkpx.gr), @"gr",
		BIGNUM2NSString(step1.p1.zkpx.b), @"b",
		_signerIdentity, @"id",
		nil];

	NSDictionary* zkp2 = [NSDictionary dictionaryWithObjectsAndKeys:
		BIGNUM2NSString(step1.p2.zkpx.gr), @"gr",
		BIGNUM2NSString(step1.p2.zkpx.b), @"b",
		_signerIdentity, @"id",
		nil];
	
	NSDictionary* result = [NSDictionary dictionaryWithObjectsAndKeys:
		BIGNUM2NSString(step1.p1.gx), @"gx1",
		BIGNUM2NSString(step1.p2.gx), @"gx2",
		zkp1, @"zkp1",
		zkp2, @"zkp2",
		nil];
		
	JPAKE_STEP1_release(&step1);
	
	return result;
}

- (NSDictionary*) generateMessageTwoFromMessageOne: (NSDictionary*) one
{
	JPAKE_STEP1 step1;
	JPAKE_STEP1_init(&step1);
	
	NSString2BIGNUM([one objectForKey: @"gx1"], &step1.p1.gx);
	NSString2BIGNUM([[one objectForKey: @"zkp1"] objectForKey: @"b"], &step1.p1.zkpx.b);
	NSString2BIGNUM([[one objectForKey: @"zkp1"] objectForKey: @"gr"], &step1.p1.zkpx.gr);
	NSString2BIGNUM([one objectForKey: @"gx2"], &step1.p2.gx);
	NSString2BIGNUM([[one objectForKey: @"zkp2"] objectForKey: @"b"], &step1.p2.zkpx.b);
	NSString2BIGNUM([[one objectForKey: @"zkp2"] objectForKey: @"gr"], &step1.p2.zkpx.gr);
	
	NSDictionary* result = nil;
	
	if (JPAKE_STEP1_process(_ctx, &step1))
	{
		JPAKE_STEP2 step2;
		JPAKE_STEP2_init(&step2);
		
		JPAKE_STEP2_generate(&step2, _ctx);
		
		NSDictionary* zkp_A = [NSDictionary dictionaryWithObjectsAndKeys:
			BIGNUM2NSString(step2.zkpx.gr), @"gr",
			BIGNUM2NSString(step2.zkpx.b), @"b",
			_signerIdentity, @"id",
			nil];
	
		result = [NSDictionary dictionaryWithObjectsAndKeys:
			BIGNUM2NSString(step2.gx), @"A",
			zkp_A, @"zkp_A",
			nil];
			
		JPAKE_STEP2_release(&step2);
	}
	
	JPAKE_STEP1_release(&step1);
	
	return result;
}

- (NSData*) generateKeyFromMessageTwo: (NSDictionary*) two
{
	JPAKE_STEP2 step2;
	JPAKE_STEP2_init(&step2);
	
	NSString2BIGNUM([two objectForKey: @"A"], &step2.gx);
	NSString2BIGNUM([[two objectForKey: @"zkp_A"] objectForKey: @"b"], &step2.zkpx.b);
	NSString2BIGNUM([[two objectForKey: @"zkp_A"] objectForKey: @"gr"], &step2.zkpx.gr);

	NSData* result = nil;

	if (JPAKE_STEP2_process(_ctx, &step2))
	{
		const BIGNUM* key = JPAKE_get_shared_key(_ctx);
		if (key != nil) {
			char* data = malloc(BN_num_bytes(key));
			BN_bn2bin(key, (void*) data);
			result = [NSData dataWithBytesNoCopy: data length: BN_num_bytes(key) freeWhenDone: YES];
		}
	}
	
	JPAKE_STEP2_release(&step2);

	return result;
}

@end
