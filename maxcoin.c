#include <string.h>
#include <stdint.h>

//#include "sph_keccak.h"
#include "cpuminer-config.h"
#include "miner.h"
#include "KeccakSponge.h"

spongeState keccak512_init;

static void keccakhash(void *state, const void *input)
{
    spongeState keccak512_tmp;
    memcpy(&keccak512_tmp, &keccak512_init, sizeof(keccak512_init));
    Absorb(&keccak512_tmp, input, 80*8);
    Squeeze(&keccak512_tmp, state, 32*8);
}

int scanhash_keccak(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t hash64[8] __attribute__((aligned(32)));
	uint32_t endiandata[32];

	int kk=0;
	for (; kk < 32; kk++)
	{
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};	
	
	do {
	
		pdata[19] = ++n;
		be32enc(&endiandata[19], n); 
		keccakhash(hash64, &endiandata);
                if (((hash64[7]&0xFFFFFF00)==0) && 
				fulltest(hash64, ptarget)) {
                       *hashes_done = n - first_nonce + 1;
			return true;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
