#include "MyForm.h"

using namespace System;
using namespace System::Windows::Forms;
//using namespace RSAForm;

[STAThread]
int main(array<String^>^ args)
{
    Application::EnableVisualStyles();
    Application::SetCompatibleTextRenderingDefault(false);
    Application::Run(gcnew RSAForm());
    return 0;
}

