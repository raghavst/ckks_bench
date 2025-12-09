#include <benchmark/benchmark.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>

#include "UserInterface.h"

using json = nlohmann::json;
using word = uint32_t;
using namespace cheddar;

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
    int log_degree_;
    double default_scale_;
    int default_encryption_level_;
    std::vector<word> main_primes_;
    std::vector<word> ter_primes_;
    std::vector<word> aux_primes_;
    std::vector<std::pair<int, int>> level_config_;
    std::pair<int, int> additional_base_;

    std::unique_ptr<Parameter<word>> params = nullptr;
    ContextPtr<word> context = nullptr;
    std::unique_ptr<UserInterface<word>> interface = nullptr;

public:
    void Check(bool condition, const std::string &message) {
        if (!condition) {
            std::cerr << "ERROR:" << message << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    void SetUp(const ::benchmark::State& state) override {
        std::string json_path("bootparam_30_custom.json");
        std::ifstream json_file(json_path);
        Check(json_file.is_open(), "Failed to open JSON file: " + json_path);
        json json_data = json::parse(json_file);
        json_file.close();

        // Parsing...
        Check(json_data.contains("log_degree"), "Missing log_degree in JSON file");
        Check(json_data["log_degree"].is_number_integer(),
            "log_degree should be an integer");
        log_degree_ = json_data["log_degree"];

        Check(json_data.contains("log_default_scale"),
            "Missing log_default_scale in JSON file");
        Check(json_data["log_default_scale"].is_number_integer(),
            "log_default_scale should be an integer");
        int log_default_scale = json_data["log_default_scale"];
        default_scale_ = (UINT64_C(1) << log_default_scale);

        Check(json_data.contains("default_encryption_level"),
            "Missing default_encryption_level in JSON file");
        Check(json_data["default_encryption_level"].is_number_integer(),
            "default_encryption_level should be an integer");
        default_encryption_level_ = json_data["default_encryption_level"];

        main_primes_.clear();
        Check(json_data.contains("main_primes"),
            "Missing main_primes in JSON file");
        auto main_primes = json_data["main_primes"];
        Check(main_primes.is_array(), "main_primes should be an array");
        std::vector<word> main_primes_;
        for (const auto &prime : main_primes) {
        Check(prime.is_number_integer(),
                "main_primes should be an array of integers");
        main_primes_.push_back(prime);
        }

        ter_primes_.clear();
        if (json_data.contains("terminal_primes")) {
        auto ter_primes = json_data["terminal_primes"];
        Check(ter_primes.is_array(), "aux_primes should be an array");
        for (const auto &prime : ter_primes) {
            Check(prime.is_number_integer(),
                "terminal_primes should be an array of integers");
            ter_primes_.push_back(prime);
        }
        }

        aux_primes_.clear();
        Check(json_data.contains("auxiliary_primes"),
            "Missing auxiliary_primes in JSON file");
        auto aux_primes = json_data["auxiliary_primes"];
        Check(aux_primes.is_array(), "aux_primes should be an array");
        for (const auto &prime : aux_primes) {
        Check(prime.is_number_integer(),
                "auxiliary_primes should be an array of integers");
        aux_primes_.push_back(prime);
        }

        level_config_.clear();
        Check(json_data.contains("level_config"),
            "Missing level_config in JSON file");
        auto level_config = json_data["level_config"];
        Check(level_config.is_array(), "level_config should be an array");
        for (const auto &pair : level_config) {
        Check(pair.is_array() && pair.size() == 2,
                "level_config should be an array of pairs");
        level_config_.emplace_back(pair[0], pair[1]);
        }

        additional_base_ = {0, 0};
        if (json_data.contains("additional_base")) {
        auto additional_base = json_data["additional_base"];
        Check(additional_base.is_array() && additional_base.size() == 2,
                "additional_base should be an array of pairs");
        additional_base_ = {additional_base[0], additional_base[1]};
        }

        // Initialize Parameter
        params = std::make_unique<Parameter<word>>(
            log_degree_, default_scale_, default_encryption_level_, level_config_,
            main_primes_, aux_primes_, ter_primes_, additional_base_);
        context = Context<word>::Create(*params);
        interface = std::make_unique<UserInterface<word>>(context);
    }

    void TearDown(const ::benchmark::State& state) override {
        interface.reset();
        context.reset();
        params.reset();
    }

    double DetermineScale(int level) const {
        if (level <= default_encryption_level_) {
        return params->GetScale(level);
        } else {
        // We just use rescale prime product as the scale for test purposes.
        return params->GetRescalePrimeProd(level);
        }
    }

    void Encode(Plaintext<word> &res, const std::vector<Complex> &msg, int level,
                bool mod_up = false) const {
        int num_q_primes = params->LevelToNP(level).GetNumQ();
        int num_p_primes = mod_up ? params->alpha_ : 0;
        double scale = DetermineScale(level);
        context->encoder_.Encode(res, level, scale, msg, num_p_primes);
    }

    void EncodeAndEncrypt(Ciphertext<word> &res, const std::vector<Complex> &msg,
                            int level, bool mod_up = false) const {
        Plaintext<word> ptxt;
        Encode(ptxt, msg, level, mod_up);
        interface->Encrypt(res, ptxt);
    }

    std::tuple<Ciphertext<word>, Ciphertext<word>> PopulateObjects() {
        std::vector<Complex> x1;
        std::vector<Complex> x2;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        const int row_size = params->log_degree_ / 2;
        for (size_t i = 0; i < row_size; i++) {
            x1.push_back(dis(gen));
            x2.push_back(dis(gen));
        }   

        Ciphertext<word> ctxt1, ctxt2;
        int level = params->max_level_;
        Plaintext<word> ptxt1;
        EncodeAndEncrypt(ctxt1, x1, level);
        EncodeAndEncrypt(ctxt2, x2, level);

        return std::make_tuple(std::move(ctxt1), std::move(ctxt2));
    }

};

BENCHMARK_F(CustomBenchmarkFixture, HAdd)(benchmark::State& state) {
    auto [ctxt1, ctxt2] = PopulateObjects();

    for (auto _ : state) {
        state.PauseTiming();          
        Ciphertext<word> temp_ctxt;
        CudaSyncCheckError;
        state.ResumeTiming();  
        context->Add(temp_ctxt, ctxt1, ctxt2);
        CudaSyncCheckError;
    }
}

BENCHMARK_F(CustomBenchmarkFixture, HMult)(benchmark::State& state) {
    auto [ctxt1, ctxt2] = PopulateObjects();

    for (auto _ : state) {
        state.PauseTiming();          
        Ciphertext<word> temp_ctxt;
        CudaSyncCheckError;
        state.ResumeTiming();
        context->HMult(temp_ctxt, ctxt1, ctxt2, interface->GetMultiplicationKey(), false);
        CudaSyncCheckError;
    }
}

BENCHMARK_F(CustomBenchmarkFixture, Rescale)(benchmark::State& state) {
    auto [ctxt1, ctxt2] = PopulateObjects();

    for (auto _ : state) {
        state.PauseTiming();          
        Ciphertext<word> temp_ctxt, temp_ctxt2;
        context->HMult(temp_ctxt, ctxt1, ctxt2, interface->GetMultiplicationKey(), false);
        CudaSyncCheckError;
        state.ResumeTiming();
        context->Rescale(temp_ctxt2, temp_ctxt);
        CudaSyncCheckError;
    }
}

BENCHMARK_F(CustomBenchmarkFixture, HRotate)(benchmark::State& state) {
    auto [ctxt1, ctxt2] = PopulateObjects();
    interface->PrepareRotationKey(1, params->max_level_);

    for (auto _ : state) {
        state.PauseTiming();          
        Ciphertext<word> temp_ctxt;
        CudaSyncCheckError;
        state.ResumeTiming();  
        context->HRot(temp_ctxt, ctxt1, interface->GetRotationKey(1), 1);
        CudaSyncCheckError;
    }
}

BENCHMARK_MAIN();