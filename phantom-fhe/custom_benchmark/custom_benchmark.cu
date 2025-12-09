#include <benchmark/benchmark.h>
#include <memory>

#include "context.cuh"
#include "phantom.h"

#define CudaSyncCheckError                                                                     \
    do {                                                                                       \
        cudaDeviceSynchronize();                                                               \
        cudaError_t err = cudaGetLastError();                                                  \
        if (err != cudaSuccess) {                                                              \
            printf("Cuda failure %s:%d: '%s'\n", __FILE__, __LINE__, cudaGetErrorString(err)); \
            exit(EXIT_FAILURE);                                                                \
        }                                                                                      \
    } while (0)

class CustomBenchmarkFixture : public benchmark::Fixture {
protected:
    phantom::EncryptionParameters params;
    double scale;

public:
    void SetUp(const ::benchmark::State& state) override {
        params = phantom::EncryptionParameters(phantom::scheme_type::ckks);
        std::vector<int> galois_steps = {1};
        size_t poly_modulus_degree = 1 << 16;
        params.set_poly_modulus_degree(poly_modulus_degree);
        params.set_galois_elts(phantom::util::get_elts_from_steps(galois_steps, 
                poly_modulus_degree));
        params.set_coeff_modulus(phantom::arith::CoeffModulus::Create(
                poly_modulus_degree, {60, 30, 30, 30, 30, 30, 30, 30,
                                        30, 30, 30, 30, 30, 30, 30, 30,
                                        30, 30, 30, 30, 30, 30, 30, 30,
                                        60, 60, 60, 60, 60, 60}));
        params.set_special_modulus_size(6);
        scale = pow(2.0, 30);
    }

    std::tuple<PhantomSecretKey, PhantomPublicKey, PhantomRelinKey,
            PhantomGaloisKey, PhantomCiphertext, PhantomCiphertext> 
            PopulateObjects(PhantomContext& context) {
        PhantomSecretKey skey = PhantomSecretKey(context);
        PhantomPublicKey pkey = PhantomPublicKey(skey.gen_publickey(context));
        PhantomRelinKey rkey = PhantomRelinKey(skey.gen_relinkey(context));
        PhantomGaloisKey gkey = PhantomGaloisKey(skey.create_galois_keys(context));

        std::vector<double> x1;
        std::vector<double> x2;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        PhantomCKKSEncoder ckks_encoder(context);
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++) {
            x1.push_back(dis(gen));
            x2.push_back(dis(gen));
        }   

        PhantomPlaintext ptxt1;
        PhantomPlaintext ptxt2;
        PhantomCiphertext ctxt1;
        PhantomCiphertext ctxt2;
        ckks_encoder.encode(context, x1, scale, ptxt1);
        ckks_encoder.encode(context, x2, scale, ptxt2);
        pkey.encrypt_asymmetric(context, ptxt1, ctxt1);
        pkey.encrypt_asymmetric(context, ptxt2, ctxt2);

        return std::make_tuple(std::move(skey), std::move(pkey),
            std::move(rkey), std::move(gkey), std::move(ctxt1),
            std::move(ctxt2));
    }

};

BENCHMARK_F(CustomBenchmarkFixture, HAdd)(benchmark::State& state) {
    PhantomContext context(params);
    auto [skey, pkey, rkey, gkey, ctxt1, ctxt2] = PopulateObjects(context);

    for (auto _ : state) {
        state.PauseTiming();          
        PhantomCiphertext temp_ctxt(ctxt1);
        CudaSyncCheckError;
        state.ResumeTiming();  
        phantom::add_inplace(context, temp_ctxt, ctxt2);
        CudaSyncCheckError;
    }
}

BENCHMARK_F(CustomBenchmarkFixture, HMult)(benchmark::State& state) {
    PhantomContext context(params);
    auto [skey, pkey, rkey, gkey, ctxt1, ctxt2] = PopulateObjects(context);

    for (auto _ : state) {
        state.PauseTiming();          
        PhantomCiphertext temp_ctxt(ctxt1);
        CudaSyncCheckError;
        state.ResumeTiming();  
        phantom::multiply_inplace(context, temp_ctxt, ctxt2);
        phantom::relinearize_inplace(context, temp_ctxt, rkey);
        CudaSyncCheckError;
    }
}

BENCHMARK_F(CustomBenchmarkFixture, Rescale)(benchmark::State& state) {
    PhantomContext context(params);
    auto [skey, pkey, rkey, gkey, ctxt1, ctxt2] = PopulateObjects(context);

    for (auto _ : state) {
        state.PauseTiming();          
        PhantomCiphertext temp_ctxt(ctxt1);  
        phantom::multiply_inplace(context, temp_ctxt, ctxt2);
        phantom::relinearize_inplace(context, temp_ctxt, rkey);
        CudaSyncCheckError;
        state.ResumeTiming();
        phantom::rescale_to_next_inplace(context, temp_ctxt);
        CudaSyncCheckError;
    }
}

BENCHMARK_F(CustomBenchmarkFixture, HRotate)(benchmark::State& state) {
    PhantomContext context(params);
    auto [skey, pkey, rkey, gkey, ctxt1, ctxt2] = PopulateObjects(context);

    for (auto _ : state) {
        state.PauseTiming();          
        PhantomCiphertext temp_ctxt(ctxt1);
        CudaSyncCheckError;
        state.ResumeTiming();  
        phantom::rotate_inplace(context, temp_ctxt, 1, gkey);
        CudaSyncCheckError;
    }
}

BENCHMARK_MAIN();