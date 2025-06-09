#include <string>
#include <sstream>
#include <random>
#include <ctime>
#include <msclr/marshal_cppstd.h>

using namespace System;
using namespace System::Numerics;
using namespace System::Windows::Forms;
using namespace System::Diagnostics;

public ref class RSAForm : public Form
{
private:
    Button^ btnGenerateKeys;
    Button^ btnEncrypt;
    Button^ btnDecrypt;
    Button^ btnShowKeys;
    TextBox^ txtInput;
    TextBox^ txtEncrypted;
    TextBox^ txtDecrypted;
    Label^ lblInput;
    Label^ lblEncrypted;
    Label^ lblDecrypted;
    Label^ lblKeySize;
    NumericUpDown^ numKeySize;
    Label^ lblEncryptTime;
    Label^ lblDecryptTime;

    // RSA переменные
    BigInteger p, q, n, phi, publicKey, d;
    bool keysGenerated = false;

    Random^ rng = gcnew Random();

public:
    RSAForm()
    {
        InitializeComponent();
    }

private:
    void InitializeComponent()
    {
        this->Text = "RSA Шифрование (BigInteger)";
        this->Size = System::Drawing::Size(600, 500);

        btnGenerateKeys = gcnew Button();
        btnGenerateKeys->Text = "Сгенерировать ключи";
        btnGenerateKeys->Location = Drawing::Point(10, 10);
        btnGenerateKeys->Size = Drawing::Size(180, 30);
        btnGenerateKeys->Click += gcnew EventHandler(this, &RSAForm::GenerateKeys_Click);

        btnEncrypt = gcnew Button();
        btnEncrypt->Text = "Зашифровать";
        btnEncrypt->Location = Drawing::Point(200, 10);
        btnEncrypt->Size = Drawing::Size(120, 30);
        btnEncrypt->Click += gcnew EventHandler(this, &RSAForm::Encrypt_Click);

        btnDecrypt = gcnew Button();
        btnDecrypt->Text = "Расшифровать";
        btnDecrypt->Location = Drawing::Point(330, 10);
        btnDecrypt->Size = Drawing::Size(120, 30);
        btnDecrypt->Click += gcnew EventHandler(this, &RSAForm::Decrypt_Click);

        btnShowKeys = gcnew Button();
        btnShowKeys->Text = "Показать ключи";
        btnShowKeys->Location = Drawing::Point(460, 10);
        btnShowKeys->Size = Drawing::Size(120, 30);
        btnShowKeys->Click += gcnew EventHandler(this, &RSAForm::ShowKeys_Click);

        txtInput = gcnew TextBox();
        txtInput->Multiline = true;
        txtInput->Location = Drawing::Point(10, 70);
        txtInput->Size = Drawing::Size(570, 60);

        txtEncrypted = gcnew TextBox();
        txtEncrypted->Multiline = true;
        txtEncrypted->ReadOnly = true;
        txtEncrypted->Location = Drawing::Point(10, 160);
        txtEncrypted->Size = Drawing::Size(570, 100);
        txtEncrypted->ScrollBars = ScrollBars::Vertical;  // Добавили вертикальный скролл
        txtEncrypted->Font = gcnew Drawing::Font("Consolas", 9);  // Моноширинный шрифт для лучшего отображения

        txtDecrypted = gcnew TextBox();
        txtDecrypted->Multiline = true;
        txtDecrypted->ReadOnly = true;
        txtDecrypted->Location = Drawing::Point(10, 280);
        txtDecrypted->Size = Drawing::Size(570, 60);

        lblInput = gcnew Label();
        lblInput->Text = "Исходное сообщение:";
        lblInput->Location = Drawing::Point(10, 50);

        lblEncrypted = gcnew Label();
        lblEncrypted->Text = "Зашифрованное:";
        lblEncrypted->Location = Drawing::Point(10, 140);

        lblDecrypted = gcnew Label();
        lblDecrypted->Text = "Расшифрованное:";
        lblDecrypted->Location = Drawing::Point(10, 260);

        lblKeySize = gcnew Label();
        lblKeySize->Text = "Размер ключа (бит):";
        lblKeySize->Location = Drawing::Point(10, 348);

        numKeySize = gcnew NumericUpDown();
        numKeySize->Minimum = 8;
        numKeySize->Maximum = 4096;
        numKeySize->Increment = 8;
        numKeySize->Value = 1024; // Увеличено значение по умолчанию
        numKeySize->Location = Drawing::Point(150, 348);

        lblEncryptTime = gcnew Label();
        lblEncryptTime->Location = Drawing::Point(10, 370);
        lblEncryptTime->AutoSize = true;

        lblDecryptTime = gcnew Label();
        lblDecryptTime->Location = Drawing::Point(10, 400);
        lblDecryptTime->AutoSize = true;

        Controls->AddRange(gcnew array<Control^>{
            btnGenerateKeys, btnEncrypt, btnDecrypt, btnShowKeys,
                txtInput, txtEncrypted, txtDecrypted,
                lblInput, lblEncrypted, lblDecrypted, lblKeySize,
                numKeySize, lblEncryptTime, lblDecryptTime
        });
    }

    // === RSA ===

    BigInteger GenerateRandomPrime(int bits)
    {
        while (true)
        {
            array<Byte>^ data = gcnew array<Byte>((bits + 7) / 8);
            rng->NextBytes(data);
            data[data->Length - 1] |= 0x80; // ensure MSB set
            data[0] |= 1; // ensure odd
            BigInteger candidate(data);

            // Добавлена проверка на размер числа
            BigInteger maxValue = BigInteger::Pow(2, bits) - 1;
            if (candidate > maxValue)
                candidate = maxValue;

            if (candidate.Sign < 0) candidate = -candidate;

            if (IsProbablePrime(candidate, 20, bits))
                return candidate;
        }
    }

    bool IsProbablePrime(BigInteger n, int k, int keyBits)
    {
        if (n < (BigInteger)2) return false;
        if (n == (BigInteger)2 || n == (BigInteger)3) return true;
        if (n % 2 == (BigInteger)0) return false;

        BigInteger d = n - (BigInteger)1;
        int s = 0;
        while (d % 2 == (BigInteger)0)
        {
            d /= 2;
            s++;
        }

        for (int i = 0; i < k; i++)
        {
            BigInteger maxRandom = n - 4;
            BigInteger a;

            int numBytes = (keyBits + 7) / 8;
            array<Byte>^ bytes = gcnew array<Byte>(numBytes);
            rng->NextBytes(bytes);

            BigInteger aCandidate(bytes);
            a = (aCandidate % maxRandom) + 2;

            BigInteger x = BigInteger::ModPow(a, d, n);
            if (x == (BigInteger)1 || x == n - (BigInteger)1)
                continue;

            bool continueLoop = false;
            for (int r = 1; r < s; r++)
            {
                x = BigInteger::ModPow(x, 2, n);
                if (x == (BigInteger)1) return false;
                if (x == n - (BigInteger)1)
                {
                    continueLoop = true;
                    break;
                }
            }
            if (!continueLoop)
                return false;
        }
        return true;
    }


    BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger m0 = m, t, q;
        BigInteger x0 = 0, x1 = 1;

        while (a > (BigInteger)1)
        {
            q = a / m;
            t = m;
            m = a % m;
            a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if (x1 < (BigInteger)0)
            x1 += m0;
        return x1;
    }

    void GenerateKeys_Click(Object^ sender, EventArgs^ e)
    {
        int bits = (int)numKeySize->Value;

        try
        {
            p = GenerateRandomPrime(bits / 2);
            q = GenerateRandomPrime(bits / 2);
            n = p * q;
            phi = (p - (BigInteger)1) * (q - (BigInteger)1);

            publicKey = (BigInteger)65537;
            while (BigInteger::GreatestCommonDivisor((BigInteger)publicKey, (BigInteger)phi) != (BigInteger)1)
                publicKey = publicKey + 2;

            d = ModInverse(publicKey, phi);
            keysGenerated = true;

            MessageBox::Show("Ключи сгенерированы успешно!", "RSA", MessageBoxButtons::OK, MessageBoxIcon::Information);
        }
        catch (Exception^ ex)
        {
            MessageBox::Show("Ошибка генерации ключей: " + ex->Message, "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
        }
    }

    void Encrypt_Click(Object^ sender, EventArgs^ e)
    {
        if (!keysGenerated)
        {
            MessageBox::Show("Сначала сгенерируйте ключи!");
            return;
        }

        try
        {
            String^ input = txtInput->Text;
            if (String::IsNullOrEmpty(input))
            {
                MessageBox::Show("Введите текст для шифрования!");
                return;
            }

            std::string mstr = msclr::interop::marshal_as<std::string>(input);
            std::stringstream ss;

            Stopwatch^ sw = Stopwatch::StartNew();
            for (unsigned char ch : mstr)  // Используем unsigned char
            {
                BigInteger m = (BigInteger)ch;  // Безопасное преобразование
                BigInteger c = BigInteger::ModPow(m, publicKey, n);
                std::string cstr = msclr::interop::marshal_as<std::string>(c.ToString());
                ss << cstr << " ";
            }
            sw->Stop();

            txtEncrypted->Text = gcnew String(ss.str().c_str());
            lblEncryptTime->Text = "Время шифрования: " + sw->ElapsedMilliseconds + " мс";
        }
        catch (Exception^ ex)
        {
            MessageBox::Show("Ошибка шифрования: " + ex->Message, "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
        }
    }

    void Decrypt_Click(Object^ sender, EventArgs^ e)
    {
        if (!keysGenerated)
        {
            MessageBox::Show("Сначала сгенерируйте ключи!");
            return;
        }

        try
        {
            String^ encryptedText = txtEncrypted->Text;
            if (String::IsNullOrEmpty(encryptedText))
            {
                MessageBox::Show("Нет данных для расшифровки!");
                return;
            }

            std::stringstream ss(msclr::interop::marshal_as<std::string>(encryptedText));
            std::string output;
            std::string token;

            Stopwatch^ sw = Stopwatch::StartNew();
            while (ss >> token)
            {
                BigInteger c = BigInteger::Parse(gcnew String(token.c_str()));
                BigInteger m = BigInteger::ModPow(c, d, n);
                output += (char)(int)m;
            }
            sw->Stop();

            txtDecrypted->Text = gcnew String(output.c_str());
            lblDecryptTime->Text = "Время расшифровки: " + sw->ElapsedMilliseconds + " мс";
        }
        catch (Exception^ ex)
        {
            MessageBox::Show("Ошибка расшифровки: " + ex->Message, "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
        }
    }

    void ShowKeys_Click(Object^ sender, EventArgs^ e)
    {
        if (!keysGenerated)
        {
            MessageBox::Show("Ключи еще не сгенерированы.");
            return;
        }

        String^ info = "Ключи RSA\n\n" +
            "p = " + p + "\n" +
            "q = " + q + "\n" +
            "n = " + n + "\n" +
            "phi = " + phi + "\n\n" +
            "Открытый ключ: (" + publicKey + ", " + n + ")\n" +
            "Закрытый ключ: (" + d + ", " + n + ")";

        MessageBox::Show(info, "RSA Ключи", MessageBoxButtons::OK, MessageBoxIcon::Information);
    }
};