# USBKeyCryptoValidator

USB 하드웨어 ID를 활용한 USB 장치의 유효성을 인증하는 프로그램입니다.
C++, WMI, openssl 라이브러리를 활용하여 구현하였습니다. 

총 4개의 디렉토리로 구성되어 있습니다.

include
    AES 암호화 기능을 사용하기 위해 openssl 라이브러리를 저장한 디렉토리

UsbKeyCryptoValidator
    USB 하드웨어 암호화와 복호화 기능을 제공하는 UsbKeyCryptoValidator 라이브러리 파일을 생성하는 프로젝트
    TestProject와 USBKeyMaker 프로젝트들은 해당 라이브러리를 사용해 동작합니다.

USBKeyMaker
    USB 장치에 암호화 파일을 생성하는 프로젝트
    C++ MFC로 UI를 구성하였습니다.

TestProject
    사용자의 PC에 연결된 USB에 저장한 암호화 파일의 유효성을 검증하는 프로젝트
    간단한 테스트를 위해 콘솔 프로그램으로 구현하였습니다.

* 암호화 키는 라이브러리 내부에 정의된 임의의 키를 사용합니다.
