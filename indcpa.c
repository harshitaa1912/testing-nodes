

#include "indcpa.h"

#include "debug.h"
#include "randombytes.h"
#include "sampling.h"
#include "symmetric.h"
#include "verify.h"

#define mlk_pack_pk MLK_ADD_PARAM_SET(mlk_pack_pk)
#define mlk_unpack_pk MLK_ADD_PARAM_SET(mlk_unpack_pk)
#define mlk_pack_sk MLK_ADD_PARAM_SET(mlk_pack_sk)
#define mlk_unpack_sk MLK_ADD_PARAM_SET(mlk_unpack_sk)
#define mlk_pack_ciphertext MLK_ADD_PARAM_SET(mlk_pack_ciphertext)
#define mlk_unpack_ciphertext MLK_ADD_PARAM_SET(mlk_unpack_ciphertext)
#define mlk_matvec_mul MLK_ADD_PARAM_SET(mlk_matvec_mul)
#define mlk_polymat_permute_bitrev_to_custom \
  MLK_ADD_PARAM_SET(mlk_polymat_permute_bitrev_to_custom)
#define mlk_keypair_getnoise_eta1 MLK_ADD_PARAM_SET(mlk_keypair_getnoise_eta1)
#define mlk_enc_getnoise_eta1_eta2 MLK_ADD_PARAM_SET(mlk_enc_getnoise_eta1_eta2)

#if !defined(MLK_CONFIG_NO_KEYPAIR_API)
static void mlk_pack_pk(uint8_t r[MLKEM_INDCPA_PUBLICKEYBYTES],
                        const mlk_polyvec *pk,
                        const uint8_t seed[MLKEM_SYMBYTES])
{
  mlk_assert_bound_2d(pk->vec, MLKEM_K, MLKEM_N, 0, MLKEM_Q);
  mlk_polyvec_tobytes(r, pk);
  mlk_memcpy(r + MLKEM_POLYVECBYTES, seed, MLKEM_SYMBYTES);
}
#endif

#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
static void mlk_unpack_pk(mlk_polyvec *pk, uint8_t seed[MLKEM_SYMBYTES],
                          const uint8_t packedpk[MLKEM_INDCPA_PUBLICKEYBYTES])
{
  mlk_polyvec_frombytes(pk, packedpk);
  mlk_memcpy(seed, packedpk + MLKEM_POLYVECBYTES, MLKEM_SYMBYTES);

}
#endif

#if !defined(MLK_CONFIG_NO_KEYPAIR_API)
static void mlk_pack_sk(uint8_t r[MLKEM_INDCPA_SECRETKEYBYTES],
                        const mlk_polyvec *sk)
{
  mlk_assert_bound_2d(sk->vec, MLKEM_K, MLKEM_N, 0, MLKEM_Q);
  mlk_polyvec_tobytes(r, sk);
}
#endif

#if !defined(MLK_CONFIG_NO_DECAPS_API)
static void mlk_unpack_sk(mlk_polyvec *sk,
                          const uint8_t packedsk[MLKEM_INDCPA_SECRETKEYBYTES])
{
  mlk_polyvec_frombytes(sk, packedsk);
}
#endif

#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
static void mlk_pack_ciphertext(uint8_t r[MLKEM_INDCPA_BYTES],
                                const mlk_polyvec *b, mlk_poly *v)
{
  mlk_polyvec_compress_du(r, b);
  mlk_poly_compress_dv(r + MLKEM_POLYVECCOMPRESSEDBYTES_DU, v);
}
#endif

#if !defined(MLK_CONFIG_NO_DECAPS_API)
static void mlk_unpack_ciphertext(mlk_polyvec *b, mlk_poly *v,
                                  const uint8_t c[MLKEM_INDCPA_BYTES])
{
  mlk_polyvec_decompress_du(b, c);
  mlk_poly_decompress_dv(v, c + MLKEM_POLYVECCOMPRESSEDBYTES_DU);
}
#endif

static void mlk_polymat_permute_bitrev_to_custom(mlk_polymat *a)
__contract__(

  requires(memory_no_alias(a, sizeof(mlk_polymat)))
  requires(forall(x, 0, MLKEM_K, forall(y, 0, MLKEM_K,
    array_bound(a->vec[x].vec[y].coeffs, 0, MLKEM_N, 0, MLKEM_Q))))
  assigns(memory_slice(a, sizeof(mlk_polymat)))
  ensures(forall(x, 0, MLKEM_K, forall(y, 0, MLKEM_K,
    array_bound(a->vec[x].vec[y].coeffs, 0, MLKEM_N, 0, MLKEM_Q)))))
{
#if defined(MLK_USE_NATIVE_NTT_CUSTOM_ORDER)
  unsigned i, j;
  for (i = 0; i < MLKEM_K; i++)
  __loop__(
    assigns(i, j, memory_slice(a, sizeof(mlk_polymat)))
    invariant(i <= MLKEM_K)
    invariant(forall(x2, 0, MLKEM_K, forall(y2, 0, MLKEM_K,
      array_bound(a->vec[x2].vec[y2].coeffs, 0, MLKEM_N, 0, MLKEM_Q))))
    decreases(MLKEM_K - i))
  {
    for (j = 0; j < MLKEM_K; j++)
    __loop__(
      assigns(j, memory_slice(a, sizeof(mlk_polymat)))
      invariant(i <= MLKEM_K)
      invariant(j <= MLKEM_K)
      invariant(forall(x3, 0, MLKEM_K, forall(y3, 0, MLKEM_K,
        array_bound(a->vec[x3].vec[y3].coeffs, 0, MLKEM_N, 0, MLKEM_Q))))
      decreases(MLKEM_K - j))
    {
      mlk_poly_permute_bitrev_to_custom(a->vec[i].vec[j].coeffs);
    }
  }
#else

  (void)a;
#endif
}

MLK_INTERNAL_API
void mlk_gen_matrix(mlk_polymat *a, const uint8_t seed[MLKEM_SYMBYTES],
                    int transposed)
{
  unsigned i, j;
  MLK_ALIGN uint8_t seed_ext[4][MLK_ALIGN_UP(MLKEM_SYMBYTES + 2)];

  for (j = 0; j < 4; j++)
  {
    mlk_memcpy(seed_ext[j], seed, MLKEM_SYMBYTES);
  }

#if !defined(MLK_CONFIG_SERIAL_FIPS202_ONLY)

  for (i = 0; i < (MLKEM_K * MLKEM_K / 4) * 4; i += 4)
  {
    for (j = 0; j < 4; j++)
    {
      uint8_t x, y;

      x = (uint8_t)((i + j) / MLKEM_K);
      y = (uint8_t)((i + j) % MLKEM_K);
      if (transposed)
      {
        seed_ext[j][MLKEM_SYMBYTES + 0] = x;
        seed_ext[j][MLKEM_SYMBYTES + 1] = y;
      }
      else
      {
        seed_ext[j][MLKEM_SYMBYTES + 0] = y;
        seed_ext[j][MLKEM_SYMBYTES + 1] = x;
      }
    }

    mlk_poly_rej_uniform_x4(&a->vec[i / MLKEM_K].vec[i % MLKEM_K],
                            &a->vec[(i + 1) / MLKEM_K].vec[(i + 1) % MLKEM_K],
                            &a->vec[(i + 2) / MLKEM_K].vec[(i + 2) % MLKEM_K],
                            &a->vec[(i + 3) / MLKEM_K].vec[(i + 3) % MLKEM_K],
                            seed_ext);
  }
#else

  i = 0;
#endif

  for (; i < MLKEM_K * MLKEM_K; i++)
  {
    uint8_t x, y;

    x = (uint8_t)(i / MLKEM_K);
    y = (uint8_t)(i % MLKEM_K);

    if (transposed)
    {
      seed_ext[0][MLKEM_SYMBYTES + 0] = x;
      seed_ext[0][MLKEM_SYMBYTES + 1] = y;
    }
    else
    {
      seed_ext[0][MLKEM_SYMBYTES + 0] = y;
      seed_ext[0][MLKEM_SYMBYTES + 1] = x;
    }

    mlk_poly_rej_uniform(&a->vec[i / MLKEM_K].vec[i % MLKEM_K], seed_ext[0]);
  }

  mlk_assert(i == MLKEM_K * MLKEM_K);

  mlk_polymat_permute_bitrev_to_custom(a);

  mlk_zeroize(seed_ext, sizeof(seed_ext));
}

static void mlk_matvec_mul(mlk_polyvec *out, const mlk_polymat *a,
                           const mlk_polyvec *v, const mlk_polyvec_mulcache *vc)
__contract__(
  requires(memory_no_alias(out, sizeof(mlk_polyvec)))
  requires(memory_no_alias(a, sizeof(mlk_polymat)))
  requires(memory_no_alias(v, sizeof(mlk_polyvec)))
  requires(memory_no_alias(vc, sizeof(mlk_polyvec_mulcache)))
  requires(forall(k0, 0, MLKEM_K,
    forall(k1, 0, MLKEM_K,
      array_bound(a->vec[k0].vec[k1].coeffs, 0, MLKEM_N, 0, MLKEM_UINT12_LIMIT))))
  assigns(memory_slice(out, sizeof(mlk_polyvec))))
{
  unsigned i;
  for (i = 0; i < MLKEM_K; i++)
  __loop__(
    assigns(i, memory_slice(out, sizeof(mlk_polyvec)))
    invariant(i <= MLKEM_K)
    decreases(MLKEM_K - i))
  {
    mlk_polyvec_basemul_acc_montgomery_cached(&out->vec[i], &a->vec[i], v, vc);
  }
}

#if !defined(MLK_CONFIG_NO_KEYPAIR_API)
static void mlk_keypair_getnoise_eta1(mlk_polyvec *pv, mlk_polyvec *e,
                                      const uint8_t seed[MLKEM_SYMBYTES])
__contract__(
  requires(memory_no_alias(pv, sizeof(mlk_polyvec)))
  requires(memory_no_alias(e, sizeof(mlk_polyvec)))
  requires(memory_no_alias(seed, MLKEM_SYMBYTES))
  assigns(memory_slice(pv, sizeof(mlk_polyvec)))
  assigns(memory_slice(e, sizeof(mlk_polyvec)))
  ensures(forall(k0, 0, MLKEM_K, array_abs_bound(pv->vec[k0].coeffs, 0, MLKEM_N, MLKEM_ETA1 + 1)))
  ensures(forall(k1, 0, MLKEM_K, array_abs_bound(e->vec[k1].coeffs, 0, MLKEM_N, MLKEM_ETA1 + 1)))
)
{
#if MLKEM_K == 2
  mlk_poly_getnoise_eta1_4x(&pv->vec[0], &pv->vec[1],
                            &e->vec[0], &e->vec[1],
                            seed, 0, 1, 2, 3);
#elif MLKEM_K == 3

  mlk_poly_getnoise_eta1_4x(&pv->vec[0], &pv->vec[1], &pv->vec[2], NULL, seed,
                            0, 1, 2, 0xFF);

  mlk_poly_getnoise_eta1_4x(&e->vec[0], &e->vec[1], &e->vec[2], NULL, seed, 3,
                            4, 5, 0xFF);
#elif MLKEM_K == 4
  mlk_poly_getnoise_eta1_4x(&pv->vec[0], &pv->vec[1], &pv->vec[2], &pv->vec[3],
                            seed, 0, 1, 2, 3);
  mlk_poly_getnoise_eta1_4x(&e->vec[0], &e->vec[1], &e->vec[2], &e->vec[3],
                            seed, 4, 5, 6, 7);
#endif
}
#endif

#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
static void mlk_enc_getnoise_eta1_eta2(mlk_polyvec *sp, mlk_polyvec *ep,
                                       mlk_poly *epp,
                                       const uint8_t coins[MLKEM_SYMBYTES])
__contract__(
  requires(memory_no_alias(sp, sizeof(mlk_polyvec)))
  requires(memory_no_alias(ep, sizeof(mlk_polyvec)))
  requires(memory_no_alias(epp, sizeof(mlk_poly)))
  requires(memory_no_alias(coins, MLKEM_SYMBYTES))
  assigns(memory_slice(sp, sizeof(mlk_polyvec)))
  assigns(memory_slice(ep, sizeof(mlk_polyvec)))
  assigns(memory_slice(epp, sizeof(mlk_poly)))
  ensures(forall(k0, 0, MLKEM_K, array_abs_bound(sp->vec[k0].coeffs, 0, MLKEM_N, MLKEM_ETA1 + 1)))
  ensures(forall(k1, 0, MLKEM_K, array_abs_bound(ep->vec[k1].coeffs, 0, MLKEM_N, MLKEM_ETA2 + 1)))
  ensures(array_abs_bound(epp->coeffs, 0, MLKEM_N, MLKEM_ETA2 + 1))
)
{
#if MLKEM_K == 2
  mlk_poly_getnoise_eta1122_4x(&sp->vec[0], &sp->vec[1], &ep->vec[0],
                               &ep->vec[1], coins, 0, 1, 2, 3);
  mlk_poly_getnoise_eta2(epp, coins, 4);
#elif MLKEM_K == 3

  mlk_poly_getnoise_eta1_4x(&sp->vec[0], &sp->vec[1], &sp->vec[2], NULL, coins,
                            0, 1, 2, 0xFF  );

  mlk_poly_getnoise_eta2_4x(&ep->vec[0], &ep->vec[1], &ep->vec[2], epp, coins,
                            3, 4, 5, 6);
#elif MLKEM_K == 4
  mlk_poly_getnoise_eta1_4x(&sp->vec[0], &sp->vec[1], &sp->vec[2], &sp->vec[3],
                            coins, 0, 1, 2, 3);
  mlk_poly_getnoise_eta2_4x(&ep->vec[0], &ep->vec[1], &ep->vec[2], &ep->vec[3],
                            coins, 4, 5, 6, 7);
  mlk_poly_getnoise_eta2(epp, coins, 8);
#endif
}
#endif

#if !defined(MLK_CONFIG_NO_KEYPAIR_API)
MLK_INTERNAL_API
int mlk_indcpa_keypair_derand(uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                              uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES],
                              const uint8_t coins[MLKEM_SYMBYTES],
                              MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret = 0;
  const uint8_t *publicseed;
  const uint8_t *noiseseed;
  MLK_ALLOC(buf, uint8_t, 2 * MLKEM_SYMBYTES, context);
  MLK_ALLOC(coins_with_domain_separator, uint8_t, MLKEM_SYMBYTES + 1, context);
  MLK_ALLOC(a, mlk_polymat, 1, context);
  MLK_ALLOC(e, mlk_polyvec, 1, context);
  MLK_ALLOC(pkpv, mlk_polyvec, 1, context);
  MLK_ALLOC(skpv, mlk_polyvec, 1, context);
  MLK_ALLOC(skpv_cache, mlk_polyvec_mulcache, 1, context);

  if (buf == NULL || coins_with_domain_separator == NULL || a == NULL ||
      e == NULL || pkpv == NULL || skpv == NULL || skpv_cache == NULL)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  publicseed = buf;
  noiseseed = buf + MLKEM_SYMBYTES;

  mlk_memcpy(coins_with_domain_separator, coins, MLKEM_SYMBYTES);
  coins_with_domain_separator[MLKEM_SYMBYTES] = MLKEM_K;

  mlk_hash_g(buf, coins_with_domain_separator, MLKEM_SYMBYTES + 1);

  MLK_CT_TESTING_DECLASSIFY(publicseed, MLKEM_SYMBYTES);

  mlk_gen_matrix(a, publicseed, 0  );

  mlk_keypair_getnoise_eta1(skpv, e, noiseseed);

  mlk_polyvec_ntt(skpv);
  mlk_polyvec_ntt(e);

  mlk_polyvec_mulcache_compute(skpv_cache, skpv);
  mlk_matvec_mul(pkpv, a, skpv, skpv_cache);
  mlk_polyvec_tomont(pkpv);

  mlk_polyvec_add(pkpv, e);
  mlk_polyvec_reduce(pkpv);
  mlk_polyvec_reduce(skpv);

  mlk_pack_sk(sk, skpv);
  mlk_pack_pk(pk, pkpv, publicseed);

cleanup:

  MLK_FREE(skpv_cache, mlk_polyvec_mulcache, 1, context);
  MLK_FREE(skpv, mlk_polyvec, 1, context);
  MLK_FREE(pkpv, mlk_polyvec, 1, context);
  MLK_FREE(e, mlk_polyvec, 1, context);
  MLK_FREE(a, mlk_polymat, 1, context);
  MLK_FREE(coins_with_domain_separator, uint8_t, MLKEM_SYMBYTES + 1, context);
  MLK_FREE(buf, uint8_t, 2 * MLKEM_SYMBYTES, context);
  return ret;
}
#endif

#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
MLK_INTERNAL_API
int mlk_indcpa_enc(uint8_t c[MLKEM_INDCPA_BYTES],
                   const uint8_t m[MLKEM_INDCPA_MSGBYTES],
                   const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                   const uint8_t coins[MLKEM_SYMBYTES],
                   MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret = 0;
  MLK_ALLOC(seed, uint8_t, MLKEM_SYMBYTES, context);
  MLK_ALLOC(at, mlk_polymat, 1, context);
  MLK_ALLOC(sp, mlk_polyvec, 1, context);
  MLK_ALLOC(pkpv, mlk_polyvec, 1, context);
  MLK_ALLOC(ep, mlk_polyvec, 1, context);
  MLK_ALLOC(b, mlk_polyvec, 1, context);
  MLK_ALLOC(v, mlk_poly, 1, context);
  MLK_ALLOC(k, mlk_poly, 1, context);
  MLK_ALLOC(epp, mlk_poly, 1, context);
  MLK_ALLOC(sp_cache, mlk_polyvec_mulcache, 1, context);

  if (seed == NULL || at == NULL || sp == NULL || pkpv == NULL || ep == NULL ||
      b == NULL || v == NULL || k == NULL || epp == NULL || sp_cache == NULL)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  mlk_unpack_pk(pkpv, seed, pk);
  mlk_poly_frommsg(k, m);

  MLK_CT_TESTING_DECLASSIFY(seed, MLKEM_SYMBYTES);

  mlk_gen_matrix(at, seed, 1  );

  mlk_enc_getnoise_eta1_eta2(sp, ep, epp, coins);

  mlk_polyvec_ntt(sp);

  mlk_polyvec_mulcache_compute(sp_cache, sp);
  mlk_matvec_mul(b, at, sp, sp_cache);
  mlk_polyvec_basemul_acc_montgomery_cached(v, pkpv, sp, sp_cache);

  mlk_polyvec_invntt_tomont(b);
  mlk_poly_invntt_tomont(v);

  mlk_polyvec_add(b, ep);
  mlk_poly_add(v, epp);
  mlk_poly_add(v, k);

  mlk_polyvec_reduce(b);
  mlk_poly_reduce(v);

  mlk_pack_ciphertext(c, b, v);

cleanup:

  MLK_FREE(sp_cache, mlk_polyvec_mulcache, 1, context);
  MLK_FREE(epp, mlk_poly, 1, context);
  MLK_FREE(k, mlk_poly, 1, context);
  MLK_FREE(v, mlk_poly, 1, context);
  MLK_FREE(b, mlk_polyvec, 1, context);
  MLK_FREE(ep, mlk_polyvec, 1, context);
  MLK_FREE(pkpv, mlk_polyvec, 1, context);
  MLK_FREE(sp, mlk_polyvec, 1, context);
  MLK_FREE(at, mlk_polymat, 1, context);
  MLK_FREE(seed, uint8_t, MLKEM_SYMBYTES, context);
  return ret;
}
#endif

#if !defined(MLK_CONFIG_NO_DECAPS_API)
MLK_INTERNAL_API
int mlk_indcpa_dec(uint8_t m[MLKEM_INDCPA_MSGBYTES],
                   const uint8_t c[MLKEM_INDCPA_BYTES],
                   const uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES],
                   MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret = 0;
  MLK_ALLOC(b, mlk_polyvec, 1, context);
  MLK_ALLOC(skpv, mlk_polyvec, 1, context);
  MLK_ALLOC(v, mlk_poly, 1, context);
  MLK_ALLOC(sb, mlk_poly, 1, context);
  MLK_ALLOC(b_cache, mlk_polyvec_mulcache, 1, context);

  if (b == NULL || skpv == NULL || v == NULL || sb == NULL || b_cache == NULL)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  mlk_unpack_ciphertext(b, v, c);
  mlk_unpack_sk(skpv, sk);

  mlk_polyvec_ntt(b);
  mlk_polyvec_mulcache_compute(b_cache, b);
  mlk_polyvec_basemul_acc_montgomery_cached(sb, skpv, b, b_cache);
  mlk_poly_invntt_tomont(sb);

  mlk_poly_sub(v, sb);
  mlk_poly_reduce(v);

  mlk_poly_tomsg(m, v);

cleanup:

  MLK_FREE(b_cache, mlk_polyvec_mulcache, 1, context);
  MLK_FREE(sb, mlk_poly, 1, context);
  MLK_FREE(v, mlk_poly, 1, context);
  MLK_FREE(skpv, mlk_polyvec, 1, context);
  MLK_FREE(b, mlk_polyvec, 1, context);
  return ret;
}
#endif

#undef mlk_pack_pk
#undef mlk_unpack_pk
#undef mlk_pack_sk
#undef mlk_unpack_sk
#undef mlk_pack_ciphertext
#undef mlk_unpack_ciphertext
#undef mlk_matvec_mul
#undef mlk_polymat_permute_bitrev_to_custom
#undef mlk_keypair_getnoise_eta1
#undef mlk_enc_getnoise_eta1_eta2
