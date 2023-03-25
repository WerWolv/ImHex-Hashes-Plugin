#include <hex/plugin.hpp>

#include <hex/api/content_registry.hpp>
#include <hex/ui/view.hpp>
#include <hex/providers/buffered_reader.hpp>

#include <wolv/literals.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#include <HashFactory.h>
#pragma GCC diagnostic pop

using namespace hex;
using namespace wolv::literals;

namespace {

    std::vector<u8> hashProviderRegion(const Region& region, prv::Provider *provider, auto &hashFunction) {
        auto reader = prv::ProviderReader(provider);
        reader.seek(region.getStartAddress());
        reader.setEndAddress(region.getEndAddress());

        for (u64 address = region.getStartAddress(); address < region.getEndAddress(); address += 1_MiB) {
            u64 readSize = std::min<u64>(1_MiB, (region.getEndAddress() - address) + 1);

            auto data = reader.read(address, readSize);
            hashFunction->TransformBytes({ data.begin(), data.end() }, address - region.getStartAddress(), data.size());
        }

        auto result = hashFunction->TransformFinal();

        auto bytes = result->GetBytes();
        return { bytes.begin(), bytes.end() };
    }

    class HashBasic : public ContentRegistry::Hashes::Hash {
    public:
        using FactoryFunction = IHash(*)();

        explicit HashBasic(FactoryFunction function) : Hash(function()->GetName()), m_factoryFunction(function) {}

        Function create(std::string name) override {
            return Hash::create(name, [hash = *this](const Region& region, prv::Provider *provider) -> std::vector<u8> {
                IHash hashFunction = hash.m_factoryFunction();

                hashFunction->Initialize();

                return hashProviderRegion(region, provider, hashFunction);
            });

        }

        [[nodiscard]] nlohmann::json store() const override { return { }; }
        void load(const nlohmann::json &) override {}

    private:
        FactoryFunction m_factoryFunction;
    };

    class HashWithKey : public ContentRegistry::Hashes::Hash {
    public:
        using FactoryFunction = IHashWithKey(*)();

        explicit HashWithKey(FactoryFunction function) : Hash(function()->GetName()), m_factoryFunction(function) {}

        void draw() override {
            ImGui::InputText("Key", this->m_key, ImGuiInputTextFlags_CharsHexadecimal);
        }

        Function create(std::string name) override {
            return Hash::create(name, [hash = *this, key = hex::parseByteString(this->m_key)](const Region& region, prv::Provider *provider) -> std::vector<u8> {
                IHashWithKey hashFunction = hash.m_factoryFunction();

                hashFunction->Initialize();
                hashFunction->SetKey(key);

                return hashProviderRegion(region, provider, hashFunction);
            });

        }

        [[nodiscard]] nlohmann::json store() const override { return { }; }
        void load(const nlohmann::json &) override {}

    private:
        FactoryFunction m_factoryFunction;

        std::string m_key;
    };

    class HashInitialValue : public ContentRegistry::Hashes::Hash {
    public:
        using FactoryFunction = IHash(*)(const Int32);

        explicit HashInitialValue(FactoryFunction function) : Hash(function(0)->GetName()), m_factoryFunction(function) {}

        void draw() override {
            ImGui::InputHexadecimal("Initial Value", &this->m_initialValue);
        }

        Function create(std::string name) override {
            return Hash::create(name, [hash = *this](const Region& region, prv::Provider *provider) -> std::vector<u8> {
                IHash hashFunction = hash.m_factoryFunction(Int32(hash.m_initialValue));

                hashFunction->Initialize();

                return hashProviderRegion(region, provider, hashFunction);
            });

        }

        [[nodiscard]] nlohmann::json store() const override { return { }; }
        void load(const nlohmann::json &) override {}

    private:
        FactoryFunction m_factoryFunction;
        u32 m_initialValue = 0x00;
    };

    class HashTiger : public ContentRegistry::Hashes::Hash {
    public:
        using FactoryFunction = IHash(*)(const Int32, const HashRounds&);

        explicit HashTiger(std::string name, FactoryFunction function) : Hash(std::move(name)), m_factoryFunction(function) {}
        void draw() override {
            ImGui::Combo("Hash Size", &this->m_hashSize, "128 Bits\0" "160 Bits\0" "192 Bits\0");
            ImGui::Combo("Hash Rounds", &this->m_hashRounds, "3 Rounds\0" "4 Rounds\0" "5 Rounds\0" "8 Rounds\0");
        }

        Function create(std::string name) override {
            return Hash::create(name, [hash = *this](const Region& region, prv::Provider *provider) -> std::vector<u8> {
                Int32 hashSize = 16;
                switch (hash.m_hashSize) {
                    case 0: hashSize = 16; break;
                    case 1: hashSize = 20; break;
                    case 2: hashSize = 24; break;
                }

                HashRounds hashRounds = HashRounds::Rounds3;
                switch (hash.m_hashRounds) {
                    case 0: hashRounds = HashRounds::Rounds3; break;
                    case 1: hashRounds = HashRounds::Rounds4; break;
                    case 2: hashRounds = HashRounds::Rounds5; break;
                    case 3: hashRounds = HashRounds::Rounds8; break;
                }

                IHash hashFunction = hash.m_factoryFunction(hashSize, hashRounds);

                hashFunction->Initialize();

                return hashProviderRegion(region, provider, hashFunction);
            });

        }

        [[nodiscard]] nlohmann::json store() const override { return { }; }
        void load(const nlohmann::json &) override {}

    private:
        FactoryFunction m_factoryFunction;

        int m_hashSize = 0, m_hashRounds = 0;
    };

    template<typename Config, typename T1, typename T2>
    class HashBlake2 : public ContentRegistry::Hashes::Hash {
    public:
        using FactoryFunction = IHash(*)(T1 a_Config, T2 a_TreeConfig);

        explicit HashBlake2(std::string name, FactoryFunction function) : Hash(std::move(name)), m_factoryFunction(function) {}
        void draw() override {
            ImGui::InputText("Salt", this->m_salt, ImGuiInputTextFlags_CharsHexadecimal);
            ImGui::InputText("Key", this->m_key, ImGuiInputTextFlags_CharsHexadecimal);
            ImGui::InputText("Personalization", this->m_personalization, ImGuiInputTextFlags_CharsHexadecimal);
            ImGui::Combo("Hash Size", &this->m_hashSize, "128 Bits\0" "160 Bits\0" "192 Bits\0" "224 Bits\0" "256 Bits\0" "288 Bits\0" "384 Bits\0" "512 Bits\0");

        }

        Function create(std::string name) override {
            return Hash::create(name, [hash = *this, key = hex::parseByteString(this->m_key), salt = hex::parseByteString(this->m_salt), personalization = hex::parseByteString(this->m_personalization)](const Region& region, prv::Provider *provider) -> std::vector<u8> {
                u32 hashSize = 16;
                switch (hash.m_hashSize) {
                    case 0: hashSize = 16; break;
                    case 1: hashSize = 20; break;
                    case 2: hashSize = 24; break;
                    case 3: hashSize = 28; break;
                    case 4: hashSize = 32; break;
                    case 5: hashSize = 36; break;
                    case 6: hashSize = 48; break;
                    case 7: hashSize = 64; break;
                }

                auto config = Config::GetDefaultConfig();
                config->SetKey(key);
                config->SetSalt(salt);
                config->SetPersonalization(personalization);
                config->SetHashSize(hashSize);
                IHash hashFunction = hash.m_factoryFunction(config, nullptr);

                hashFunction->Initialize();

                return hashProviderRegion(region, provider, hashFunction);
            });

        }

        [[nodiscard]] nlohmann::json store() const override { return { }; }
        void load(const nlohmann::json &) override {}

    private:
        FactoryFunction m_factoryFunction;
        std::string m_salt, m_key, m_personalization;
        int m_hashSize = 0;
    };

}


IMHEX_PLUGIN_SETUP("Extra Hashes", "WerWolv", "Plugin adding many extra hash functions") {

    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Checksum::CreateAdler32);

    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateAP);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateBKDR);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateBernstein);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateBernstein1);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateDEK);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateDJB);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateELF);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateFNV1a_32);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateFNV32);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateJS);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateOneAtTime);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreatePJW);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateRotating);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateRS);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateSDBM);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateShiftAndXor);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash32::CreateSuperFast);

    hex::ContentRegistry::Hashes::add<HashWithKey>(HashFactory::Hash32::CreateMurmur2_32);
    hex::ContentRegistry::Hashes::add<HashWithKey>(HashFactory::Hash32::CreateMurmurHash3_x86_32);
    hex::ContentRegistry::Hashes::add<HashWithKey>(HashFactory::Hash32::CreateXXHash32);

    hex::ContentRegistry::Hashes::add<HashInitialValue>(HashFactory::Hash32::CreateJenkins3);

    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash64::CreateFNV64);
    hex::ContentRegistry::Hashes::add<HashBasic>(HashFactory::Hash64::CreateFNV1a_64);

    hex::ContentRegistry::Hashes::add<HashWithKey>(HashFactory::Hash64::CreateMurmur2_64);
    hex::ContentRegistry::Hashes::add<HashWithKey>(HashFactory::Hash64::CreateSipHash64_2_4);
    hex::ContentRegistry::Hashes::add<HashWithKey>(HashFactory::Hash64::CreateXXHash64);

    hex::ContentRegistry::Hashes::add<HashWithKey>(HashFactory::Hash128::CreateSipHash128_2_4);
    hex::ContentRegistry::Hashes::add<HashWithKey>(HashFactory::Hash128::CreateMurmurHash3_x86_128);
    hex::ContentRegistry::Hashes::add<HashWithKey>(HashFactory::Hash128::CreateMurmurHash3_x64_128);

    hex::ContentRegistry::Hashes::add<HashTiger>("Tiger", HashFactory::Crypto::CreateTiger);
    hex::ContentRegistry::Hashes::add<HashTiger>("Tiger2", HashFactory::Crypto::CreateTiger2);

    hex::ContentRegistry::Hashes::add<HashBlake2<Blake2BConfig, IBlake2BConfig, IBlake2BTreeConfig>>("Blake2B", HashFactory::Crypto::CreateBlake2B);
    hex::ContentRegistry::Hashes::add<HashBlake2<Blake2SConfig, IBlake2SConfig, IBlake2STreeConfig>>("Blake2S", HashFactory::Crypto::CreateBlake2S);

}


