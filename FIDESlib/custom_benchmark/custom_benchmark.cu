#include <benchmark/benchmark.h>

#include "CKKS/ApproxModEval.cuh"
#include "CKKS/Bootstrap.cuh"
#include "CKKS/BootstrapPrecomputation.cuh"
#include "CKKS/CoeffsToSlots.cuh"
#include "CKKS/KeySwitchingKey.cuh"
#include "CKKS/Parameters.cuh"
#include "CKKS/Context.cuh"
#include <CKKS/Plaintext.cuh>
#include <CKKS/Ciphertext.cuh>

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
    lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> openFHE_params;
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc;
    FIDESlib::CKKS::RawParams raw_param;
    FIDESlib::CKKS::Parameters params;

public:
    void SetUp(const ::benchmark::State& state) override {
        openFHE_params.SetMultiplicativeDepth(23);
        openFHE_params.SetSecurityLevel(lbcrypto::HEStd_NotSet);
        openFHE_params.SetFirstModSize(60);
        openFHE_params.SetScalingModSize(30);
        openFHE_params.SetRingDim(1 << 16);
        openFHE_params.SetNumLargeDigits(4);
        openFHE_params.SetScalingTechnique(lbcrypto::FLEXIBLEAUTO);
        cc = GenCryptoContext(openFHE_params);
        cc->Enable(lbcrypto::PKE);
        cc->Enable(lbcrypto::KEYSWITCH);
        cc->Enable(lbcrypto::LEVELEDSHE);
        cc->Enable(lbcrypto::ADVANCEDSHE);
        cc->Enable(lbcrypto::FHE);
        raw_param = FIDESlib::CKKS::GetRawParams(cc);
        params = params.adaptTo(raw_param);
    }

    std::tuple<FIDESlib::CKKS::KeySwitchingKey, FIDESlib::CKKS::KeySwitchingKey, 
            FIDESlib::CKKS::RawCipherText, FIDESlib::CKKS::Ciphertext> 
    PopulateObjects(FIDESlib::CKKS::Context& context) {
        context.batch = 12;

        lbcrypto::KeyPair<lbcrypto::DCRTPoly> keys = cc->KeyGen();    
        cc->EvalMultKeyGen(keys.secretKey);
        cc->EvalRotateKeyGen(keys.secretKey, {1});

        FIDESlib::CKKS::KeySwitchingKey rkey(context);
        FIDESlib::CKKS::RawKeySwitchKey rawrkey = FIDESlib::CKKS::GetEvalKeySwitchKey(keys);
        rkey.Initialize(context, rawrkey);

        FIDESlib::CKKS::KeySwitchingKey gkey(context);
        FIDESlib::CKKS::RawKeySwitchKey rawgkey = FIDESlib::CKKS::GetRotationKeySwitchKey(keys, 1, cc);
        gkey.Initialize(context, rawgkey);

        std::vector<double> x1;
        std::vector<double> x2;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        const int row_size = 1 << 15;
        for (size_t i = 0; i < row_size; i++) {
            x1.push_back(dis(gen));
            x2.push_back(dis(gen));
        }   

        lbcrypto::Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        lbcrypto::Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2);

        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        auto c2 = cc->Encrypt(keys.publicKey, ptxt2);

        FIDESlib::CKKS::RawCipherText rawctxt1 = FIDESlib::CKKS::GetRawCipherText(cc, c1);
        FIDESlib::CKKS::RawCipherText rawctxt2 = FIDESlib::CKKS::GetRawCipherText(cc, c2);

        FIDESlib::CKKS::Ciphertext ctxt2(context, rawctxt2);

        return std::make_tuple(std::move(rkey), std::move(gkey), 
                std::move(rawctxt1), std::move(ctxt2));
    }

};

BENCHMARK_F(CustomBenchmarkFixture, HAdd)(benchmark::State& state) {
    FIDESlib::CKKS::Context context(params, {0});
    auto [rkey, gkey, rawctxt1, ctxt2] = PopulateObjects(context);

    for (auto _ : state) {
        state.PauseTiming();          
        FIDESlib::CKKS::Ciphertext temp_ctxt(context, rawctxt1);
        CudaSyncCheckError;
        state.ResumeTiming();  
        temp_ctxt.add(ctxt2);
        CudaSyncCheckError;
    }
}

BENCHMARK_F(CustomBenchmarkFixture, HMult)(benchmark::State& state) {
    FIDESlib::CKKS::Context context(params, {0});
    auto [rkey, gkey, rawctxt1, ctxt2] = PopulateObjects(context);

    for (auto _ : state) {
        state.PauseTiming();          
        FIDESlib::CKKS::Ciphertext temp_ctxt(context, rawctxt1);
        CudaSyncCheckError;
        state.ResumeTiming();  
        temp_ctxt.mult(ctxt2, rkey, false);
        CudaSyncCheckError;
    }
}

BENCHMARK_F(CustomBenchmarkFixture, Rescale)(benchmark::State& state) {
    FIDESlib::CKKS::Context context(params, {0});
    auto [rkey, gkey, rawctxt1, ctxt2] = PopulateObjects(context);

    for (auto _ : state) {
        state.PauseTiming();          
        FIDESlib::CKKS::Ciphertext temp_ctxt(context, rawctxt1);
        temp_ctxt.mult(ctxt2, rkey, false);
        CudaSyncCheckError;
        state.ResumeTiming();  
        temp_ctxt.rescale();
        CudaSyncCheckError;
    }
}

BENCHMARK_F(CustomBenchmarkFixture, HRotate)(benchmark::State& state) {
    FIDESlib::CKKS::Context context(params, {0});
    auto [rkey, gkey, rawctxt1, ctxt2] = PopulateObjects(context);

    for (auto _ : state) {
        state.PauseTiming();          
        FIDESlib::CKKS::Ciphertext temp_ctxt(context, rawctxt1);
        CudaSyncCheckError;
        state.ResumeTiming();  
        temp_ctxt.rotate(1, gkey);
        CudaSyncCheckError;
    }
}

BENCHMARK_MAIN();