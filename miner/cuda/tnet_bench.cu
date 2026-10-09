// TNet v1 attempt benchmark (SPEC.md): one mining attempt of the deep requantized int8 network PoW.
//
// Per attempt: X_0 (b x n int8) expanded from SHA256("abacus/tnet-x0" || hd || LE64(nonce)); L layers
// X_l = requant(X_{l-1} * W_l), requant(y) = clamp((y M + 2^23) >> 24), with cuBLAS int8 GEMM (tensor cores) and an integer requant kernel; then
// every ticket (row i, piece c of w bytes of X_L) is hashed with SHA-256 and compared to the target.
// Weights W_l are derived once per epoch. Byte-compatible with crates/tnet (SPEC.md).
//
// Reports per-phase medians over `attempts` (after a warm-up), the tensor-core share of the attempt,
// activation statistics of X_L, ticket counts and one sample ticket for the Rust parity check.
//
// Build: nvcc -O3 -arch=sm_75 tnet_bench.cu -lcublas -o tnet_bench
// Run:   ./tnet_bench n b L w mult attempts bits [epoch_hex hd_hex warm_s]

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <cublas_v2.h>
#include <cuda_runtime.h>

static const uint32_t hK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};
__constant__ uint32_t dK[64];

__host__ __device__ __forceinline__ uint32_t rotr(uint32_t x, int s) { return (x >> s) | (x << (32 - s)); }

template <bool DEV>
__host__ __device__ __forceinline__ void compress_w(uint32_t h[8], const uint32_t w0[16]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) w[i] = w0[i];
    for (int i = 16; i < 64; ++i)
        w[i] = w[i - 16] + (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)) + w[i - 7] +
               (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10));
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
#ifdef __CUDA_ARCH__
        const uint32_t k = dK[i];
#else
        const uint32_t k = hK[i];
#endif
        uint32_t t1 = hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + k + w[i];
        uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}
__host__ __device__ __forceinline__ void sha_init(uint32_t h[8]) {
    h[0] = 0x6a09e667; h[1] = 0xbb67ae85; h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
    h[4] = 0x510e527f; h[5] = 0x9b05688c; h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;
}
__host__ __device__ __forceinline__ uint32_t be_word(const uint8_t* b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

// Host SHA-256 of an arbitrary message.
static void hsha(const std::vector<uint8_t>& m, uint8_t out[32]) {
    uint32_t h[8], w[16];
    sha_init(h);
    std::vector<uint8_t> d = m;
    const uint64_t bits = (uint64_t)m.size() * 8;
    d.push_back(0x80);
    while (d.size() % 64 != 56) d.push_back(0);
    for (int i = 7; i >= 0; --i) d.push_back((uint8_t)(bits >> (8 * i)));
    for (size_t off = 0; off < d.size(); off += 64) {
        for (int q = 0; q < 16; ++q) w[q] = be_word(d.data() + off + 4 * q);
        compress_w<false>(h, w);
    }
    for (int i = 0; i < 8; ++i) { out[4 * i] = h[i] >> 24; out[4 * i + 1] = h[i] >> 16; out[4 * i + 2] = h[i] >> 8; out[4 * i + 3] = h[i]; }
}

// out[32 c ..) = SHA256("abacus/expand" || seed || LE32(c)); pw = first 44 bytes as words, b44 = seed[31]
struct ExpandPrefix { uint32_t pw[11]; uint32_t b44; };
static ExpandPrefix make_prefix(const uint8_t seed[32]) {
    uint8_t pre[44];
    memcpy(pre, "abacus/expand", 13);
    memcpy(pre + 13, seed, 31);
    ExpandPrefix px;
    for (int q = 0; q < 11; ++q) px.pw[q] = be_word(pre + 4 * q);
    px.b44 = seed[31];
    return px;
}
__global__ void expand_kernel(ExpandPrefix px, size_t count, uint8_t* __restrict__ out) {
    const size_t c = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (c >= count) return;
    const uint32_t cc = (uint32_t)c;
    uint32_t w[16], h[8];
    for (int i = 0; i < 11; ++i) w[i] = px.pw[i];
    w[11] = (px.b44 << 24) | ((cc & 0xff) << 16) | (((cc >> 8) & 0xff) << 8) | ((cc >> 16) & 0xff);
    w[12] = ((cc >> 24) << 24) | (0x80u << 16);
    w[13] = 0; w[14] = 0; w[15] = 49 * 8;
    sha_init(h);
    compress_w<true>(h, w);
    for (int i = 0; i < 8; ++i) {
        uint8_t* o = out + 32 * c + 4 * i;
        o[0] = h[i] >> 24; o[1] = h[i] >> 16; o[2] = h[i] >> 8; o[3] = h[i];
    }
}

// WT[j n + k] = W[k n + j]
__global__ void transpose_i8(const int8_t* __restrict__ W, int8_t* __restrict__ WT, int n) {
    __shared__ int8_t tile[32][33];
    const int bx = blockIdx.x * 32, by = blockIdx.y * 32;
    for (int y = threadIdx.y; y < 32; y += 8) tile[y][threadIdx.x] = W[(size_t)(by + y) * n + bx + threadIdx.x];
    __syncthreads();
    for (int y = threadIdx.y; y < 32; y += 8) WT[(size_t)(bx + y) * n + by + threadIdx.x] = tile[threadIdx.x][y];
}

// X = clamp((Y * M + 2^23) >> 24, -128, 127)
__device__ __forceinline__ signed char rq(int v, int M) {
    const long long t = ((long long)v * M + (1LL << 23)) >> 24;
    return (signed char)(t < -128 ? -128 : (t > 127 ? 127 : t));
}
__global__ void requant_kernel(const int32_t* __restrict__ Y, int8_t* __restrict__ X, size_t count, int M) {
    const size_t t = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= count / 4) return;
    const int4 y = reinterpret_cast<const int4*>(Y)[t];
    char4 o;
    o.x = rq(y.x, M); o.y = rq(y.y, M); o.z = rq(y.z, M); o.w = rq(y.w, M);
    reinterpret_cast<char4*>(X)[t] = o;
}

struct Suffix { uint32_t hd[8]; };  // header digest as big-endian words of its bytes

// Ticket (i, c): SHA256(X[i, c w .. (c+1) w] || 0x54 || hd || LE64 nonce || LE32 i || LE32 c); w % 64 == 0.
__global__ void ticket_kernel(const int8_t* __restrict__ X, int n, int b, int w, uint64_t nonce, const uint8_t* __restrict__ hd,
                              int bits, unsigned int* __restrict__ found, unsigned long long* __restrict__ first) {
    const int per_row = n / w;
    const size_t t = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (size_t)b * per_row) return;
    const int i = (int)(t / per_row), c = (int)(t % per_row);
    const uint32_t* piece = reinterpret_cast<const uint32_t*>(X + (size_t)i * n + (size_t)c * w);
    uint32_t h[8], wd[16];
    sha_init(h);
    for (int blk = 0; blk < w / 64; ++blk) {
        for (int q = 0; q < 16; ++q) wd[q] = __byte_perm(piece[blk * 16 + q], 0, 0x0123);
        compress_w<true>(h, wd);
    }
    uint8_t m[64];
    m[0] = 0x54;
    for (int q = 0; q < 32; ++q) m[1 + q] = hd[q];
    for (int q = 0; q < 8; ++q) m[33 + q] = (uint8_t)(nonce >> (8 * q));
    for (int q = 0; q < 4; ++q) m[41 + q] = (uint8_t)((uint32_t)i >> (8 * q));
    for (int q = 0; q < 4; ++q) m[45 + q] = (uint8_t)((uint32_t)c >> (8 * q));
    m[49] = 0x80;
    for (int q = 50; q < 56; ++q) m[q] = 0;
    const uint64_t len = ((uint64_t)w + 49) * 8;
    for (int q = 0; q < 8; ++q) m[56 + q] = (uint8_t)(len >> (8 * (7 - q)));
    for (int q = 0; q < 16; ++q) wd[q] = be_word(m + 4 * q);
    compress_w<true>(h, wd);
    // leading zero bits of the big-endian digest
    int lead = 0;
    for (int q = 0; q < 8; ++q) {
        if (h[q] == 0) { lead += 32; continue; }
        lead += __clz(h[q]);
        break;
    }
    if (lead >= bits) {
        atomicAdd(found, 1u);
        atomicCAS(first, 0xFFFFFFFFFFFFFFFFULL, ((unsigned long long)i << 32) | (unsigned)c);
    }
}

__global__ void stats_kernel(const int8_t* __restrict__ X, size_t count, unsigned long long* __restrict__ st) {
    const size_t t = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= count) return;
    const int v = X[t];
    if (v == 0) atomicAdd(&st[0], 1ULL);
    if (v == 127 || v == -128) atomicAdd(&st[1], 1ULL);
    atomicAdd(&st[2], (unsigned long long)(v < 0 ? -v : v));
}

static bool parse_hex32(const char* s, uint8_t out[32]) {
    if (strlen(s) != 64) return false;
    for (int i = 0; i < 32; ++i) { unsigned v; if (sscanf(s + 2 * i, "%2x", &v) != 1) return false; out[i] = (uint8_t)v; }
    return true;
}
static double median(std::vector<double> v) { std::sort(v.begin(), v.end()); return v[v.size() / 2]; }

int main(int argc, char** argv) {
    if (argc < 8) { fprintf(stderr, "usage: n b L w mult attempts bits [epoch_hex hd_hex warm_s]\n"); return 1; }
    const int n = atoi(argv[1]), b = atoi(argv[2]), L = atoi(argv[3]), w = atoi(argv[4]), s = atoi(argv[5]);  // s: requant multiplier M
    const int attempts = atoi(argv[6]), bits = atoi(argv[7]);
    uint8_t epoch[32], hd[32];
    memset(epoch, 0x11, 32); memset(hd, 0x22, 32);
    if (argc > 9 && (!parse_hex32(argv[8], epoch) || !parse_hex32(argv[9], hd))) { fprintf(stderr, "bad hex\n"); return 1; }
    const double warm_s = argc > 10 ? atof(argv[10]) : 3.0;
    if (n % 64 || w % 64 || n % w || b % 4 || b <= 0 || L <= 0 || s < 1) { fprintf(stderr, "bad params\n"); return 1; }
    cudaMemcpyToSymbol(dK, hK, sizeof(hK));
    cublasHandle_t cb;
    cublasCreate(&cb);
    const size_t nn = (size_t)n * n, bn = (size_t)b * n;

    // Epoch weights (once): W_l = expand(SHA256("abacus/tnet-w" || epoch || LE32(l)), n^2), stored transposed.
    std::vector<int8_t*> WT(L);
    uint8_t* tmp;
    cudaMalloc(&tmp, (nn + 31) / 32 * 32);
    auto e0w = std::chrono::high_resolution_clock::now();
    for (int l = 0; l < L; ++l) {
        std::vector<uint8_t> m((const uint8_t*)"abacus/tnet-w", (const uint8_t*)"abacus/tnet-w" + 13);
        m.insert(m.end(), epoch, epoch + 32);
        for (int q = 0; q < 4; ++q) m.push_back((uint8_t)(l >> (8 * q)));
        uint8_t sl[32];
        hsha(m, sl);
        const size_t hashes = (nn + 31) / 32;
        expand_kernel<<<(unsigned)((hashes + 255) / 256), 256>>>(make_prefix(sl), hashes, tmp);
        cudaMalloc(&WT[l], nn);
        transpose_i8<<<dim3(n / 32, n / 32), dim3(32, 8)>>>((const int8_t*)tmp, WT[l], n);
    }
    cudaDeviceSynchronize();
    const double epoch_ms = std::chrono::duration<double, std::milli>(std::chrono::high_resolution_clock::now() - e0w).count();

    int8_t *X, *X2;
    int32_t* Y;
    uint8_t* dhd;
    unsigned int* dfound;
    unsigned long long *dfirst, *dst;
    const size_t xhashes = (bn + 31) / 32;
    cudaMalloc(&X, xhashes * 32); cudaMalloc(&X2, bn); cudaMalloc(&Y, bn * 4);
    cudaMalloc(&dhd, 32); cudaMemcpy(dhd, hd, 32, cudaMemcpyHostToDevice);
    cudaMalloc(&dfound, 4); cudaMalloc(&dfirst, 8); cudaMalloc(&dst, 24);
    const int32_t alpha = 1, beta = 0;
    const size_t tickets = (size_t)b * (n / w);

    cudaEvent_t ev[2 + 2 * 64 + 2];
    for (auto& e : ev) cudaEventCreate(&e);
    std::vector<double> t_exp, t_gemm, t_req, t_hash, t_tot;
    unsigned long long total_found = 0;
    long long sample_nonce = -1, sample_i = -1, sample_c = -1;
    std::vector<int8_t> sample_piece(w);
    unsigned long long st_host[3] = {0, 0, 0};

    auto run_attempt = [&](uint64_t nonce, bool record) {
        std::vector<uint8_t> m((const uint8_t*)"abacus/tnet-x0", (const uint8_t*)"abacus/tnet-x0" + 14);
        m.insert(m.end(), hd, hd + 32);
        for (int q = 0; q < 8; ++q) m.push_back((uint8_t)(nonce >> (8 * q)));
        uint8_t xs[32];
        hsha(m, xs);
        cudaMemset(dfound, 0, 4);
        cudaMemset(dfirst, 0xFF, 8);
        cudaEventRecord(ev[0]);
        expand_kernel<<<(unsigned)((xhashes + 255) / 256), 256>>>(make_prefix(xs), xhashes, (uint8_t*)X);
        cudaEventRecord(ev[1]);
        int8_t* cur = X;
        int8_t* nxt = X2;
        for (int l = 0; l < L; ++l) {
            // Y (row-major b x n) = cur (b x n) * W_l ; column-major view: D(n x b) = WT^T-op * cur
            cublasGemmEx(cb, CUBLAS_OP_T, CUBLAS_OP_N, n, b, n, &alpha, WT[l], CUDA_R_8I, n, cur, CUDA_R_8I, n, &beta, Y,
                         CUDA_R_32I, n, CUBLAS_COMPUTE_32I, CUBLAS_GEMM_DEFAULT);
            cudaEventRecord(ev[2 + 2 * l]);
            requant_kernel<<<(unsigned)((bn / 4 + 255) / 256), 256>>>(Y, nxt, bn, s);
            cudaEventRecord(ev[3 + 2 * l]);
            std::swap(cur, nxt);
        }
        ticket_kernel<<<(unsigned)((tickets + 127) / 128), 128>>>(cur, n, b, w, nonce, dhd, bits, dfound, dfirst);
        cudaEventRecord(ev[2 + 2 * L]);
        cudaEventSynchronize(ev[2 + 2 * L]);
        if (record) {
            float ms;
            cudaEventElapsedTime(&ms, ev[0], ev[1]); t_exp.push_back(ms);
            double g = 0, r = 0;
            cudaEvent_t prev = ev[1];
            for (int l = 0; l < L; ++l) {
                cudaEventElapsedTime(&ms, prev, ev[2 + 2 * l]); g += ms;
                cudaEventElapsedTime(&ms, ev[2 + 2 * l], ev[3 + 2 * l]); r += ms;
                prev = ev[3 + 2 * l];
            }
            t_gemm.push_back(g); t_req.push_back(r);
            cudaEventElapsedTime(&ms, prev, ev[2 + 2 * L]); t_hash.push_back(ms);
            cudaEventElapsedTime(&ms, ev[0], ev[2 + 2 * L]); t_tot.push_back(ms);
            unsigned int f; unsigned long long fi;
            cudaMemcpy(&f, dfound, 4, cudaMemcpyDeviceToHost);
            cudaMemcpy(&fi, dfirst, 8, cudaMemcpyDeviceToHost);
            total_found += f;
            if (sample_nonce < 0 && fi != 0xFFFFFFFFFFFFFFFFULL) {
                sample_nonce = (long long)nonce; sample_i = (long long)(fi >> 32); sample_c = (long long)(fi & 0xFFFFFFFF);
                cudaMemcpy(sample_piece.data(), cur + (size_t)sample_i * n + (size_t)sample_c * w, w, cudaMemcpyDeviceToHost);
            }
            if (st_host[2] == 0) {
                cudaMemset(dst, 0, 24);
                stats_kernel<<<(unsigned)((bn + 255) / 256), 256>>>(cur, bn, dst);
                cudaMemcpy(st_host, dst, 24, cudaMemcpyDeviceToHost);
            }
        }
    };

    auto w0 = std::chrono::high_resolution_clock::now();
    uint64_t nonce = 1u << 30;
    while (std::chrono::duration<double>(std::chrono::high_resolution_clock::now() - w0).count() < warm_s) run_attempt(nonce++, false);
    for (int a = 0; a < attempts; ++a) run_attempt((uint64_t)a, true);

    const double macs = (double)L * b * nn, tot = median(t_tot), gm = median(t_gemm);
    printf("{\"n\": %d, \"b\": %d, \"L\": %d, \"w\": %d, \"mult\": %d, \"attempts\": %d, \"bits\": %d, \"epoch_ms\": %.1f, "
           "\"expand_ms\": %.4f, \"gemm_ms\": %.4f, \"requant_ms\": %.4f, \"hash_ms\": %.4f, \"total_ms\": %.4f, "
           "\"tensor_share\": %.4f, \"attempt_TMAC_s\": %.2f, \"gemm_TMAC_s\": %.2f, \"tickets_per_attempt\": %zu, "
           "\"ns_per_ticket\": %.2f, \"found\": %llu, \"expected_found\": %.2f, "
           "\"xl_zero_frac\": %.4f, \"xl_sat_frac\": %.4f, \"xl_mean_abs\": %.2f, ",
           n, b, L, w, s, attempts, bits, epoch_ms, median(t_exp), gm, median(t_req), median(t_hash), tot, gm / tot,
           macs / (tot / 1e3) / 1e12, macs / (gm / 1e3) / 1e12, tickets, tot * 1e6 / tickets, total_found,
           (double)attempts * tickets / (double)(1ULL << bits), (double)st_host[0] / bn, (double)st_host[1] / bn,
           (double)st_host[2] / bn);
    std::string piece;
    for (int q = 0; q < w; ++q) { char buf[3]; snprintf(buf, 3, "%02x", (uint8_t)sample_piece[q]); piece += buf; }
    printf("\"sample_nonce\": %lld, \"sample_i\": %lld, \"sample_c\": %lld, \"sample_piece\": \"%s\", \"cuda_error\": \"%s\"}\n",
           sample_nonce, sample_i, sample_c, sample_nonce >= 0 ? piece.c_str() : "", cudaGetErrorString(cudaGetLastError()));
    return 0;
}
