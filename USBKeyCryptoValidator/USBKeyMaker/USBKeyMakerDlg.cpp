#include "pch.h"
#include "framework.h"
#include "USBKeyMaker.h"
#include "USBKeyMakerDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

BEGIN_MESSAGE_MAP(CUSBKeyMakerDlg, CDialogEx)
    ON_WM_SYSCOMMAND()
    ON_WM_PAINT()
    ON_WM_QUERYDRAGICON()
    ON_MESSAGE(WM_DEVICECHANGE, &CUSBKeyMakerDlg::OnDeviceChange)
    ON_BN_CLICKED(IDC_RADIO_UNLIMIT, &CUSBKeyMakerDlg::OnBnClickedRadioUnlimit)
    ON_BN_CLICKED(IDC_RADIO_LIMIT, &CUSBKeyMakerDlg::OnBnClickedRadioLimit)
    ON_BN_CLICKED(IDC_CHECK_ALLOPTION, &CUSBKeyMakerDlg::OnBnClickedCheckAllOptions)
    ON_BN_CLICKED(IDC_BUTTON_KEY_MAKE, &CUSBKeyMakerDlg::OnBnClickedButtonKeyMake)
END_MESSAGE_MAP()

CUSBKeyMakerDlg::CUSBKeyMakerDlg(CWnd* pParent /*=nullptr*/)
    : CDialogEx(IDD_USBKEYMAKER_DIALOG, pParent) {
    m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CUSBKeyMakerDlg::DoDataExchange(CDataExchange* pDX) {
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_RADIO_UNLIMIT, m_radioUnlimit);
    DDX_Control(pDX, IDC_RADIO_LIMIT, m_radioLimit);
    DDX_Control(pDX, IDC_DATETIMEPICKER_EXPIREDATE, m_datePicker);
    DDX_Control(pDX, IDC_LIST_LOG, m_listLog);
    for (int i = 0; i < m_checkDrives.size(); ++i) {
        DDX_Control(pDX, IDC_CHECK_DRIVE1 + i, m_checkDrives[i]);
    }
    for (int i = 0; i < m_checkOptions.size(); ++i) {
        DDX_Control(pDX, IDC_CHECK_OPTION1 + i, m_checkOptions[i]);
    }
    DDX_Control(pDX, IDC_CHECK_ALLOPTION, m_checkAllOptions);
}

BOOL CUSBKeyMakerDlg::OnInitDialog() {
    CDialogEx::OnInitDialog();
    SetIcon(m_hIcon, TRUE);
    SetIcon(m_hIcon, FALSE);

    // USB 알림 등록
    DEV_BROADCAST_DEVICEINTERFACE dbi = { 0 };
    dbi.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
    dbi.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    dbi.dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE;
    m_hDeviceNotify = RegisterDeviceNotification(m_hWnd, &dbi, DEVICE_NOTIFY_WINDOW_HANDLE);

    // 초기 설정
    m_radioLimit.SetCheck(BST_CHECKED);
    m_datePicker.EnableWindow(TRUE);
    m_listLog.ResetContent();

    // USB 초기화
    InitializeUSBDisplay();

    return TRUE;
}

void CUSBKeyMakerDlg::OnSysCommand(UINT nID, LPARAM lParam) {
    if ((nID & 0xFFF0) == IDM_ABOUTBOX) {
        AfxMessageBox(L"About USB Key Encryption");
    }
    else {
        CDialogEx::OnSysCommand(nID, lParam);
    }
}

void CUSBKeyMakerDlg::OnPaint() {
    if (IsIconic()) {
        CPaintDC dc(this);
        SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);
        int cxIcon = GetSystemMetrics(SM_CXICON);
        int cyIcon = GetSystemMetrics(SM_CYICON);
        CRect rect;
        GetClientRect(&rect);
        int x = (rect.Width() - cxIcon + 1) / 2;
        int y = (rect.Height() - cyIcon + 1) / 2;
        dc.DrawIcon(x, y, m_hIcon);
    }
    else {
        CDialogEx::OnPaint();
    }
}

HCURSOR CUSBKeyMakerDlg::OnQueryDragIcon() {
    return static_cast<HCURSOR>(m_hIcon);
}

void CUSBKeyMakerDlg::InitializeUSBDisplay() {
    for (int i = 0; i < m_checkDrives.size(); ++i) {
        m_checkDrives[i].ShowWindow(SW_HIDE);
    }
    UpdateUSBDisplay();
}

void CUSBKeyMakerDlg::UpdateUSBDisplay() {
    auto usbInfoList = GetUSBInfos();
    int index = 0;

    for (const auto& usbInfo : usbInfoList) {
        if (index < m_checkDrives.size()) {
            m_checkDrives[index].SetWindowText(CString(usbInfo.drivePath.c_str()));
            m_checkDrives[index].ShowWindow(SW_SHOW);
            ++index;
        }
    }

    for (; index < m_checkDrives.size(); ++index) {
        m_checkDrives[index].SetWindowText(L"");
        m_checkDrives[index].ShowWindow(SW_HIDE);
    }
}

LRESULT CUSBKeyMakerDlg::OnDeviceChange(WPARAM wParam, LPARAM lParam) {
    if (wParam == DBT_DEVICEARRIVAL || wParam == DBT_DEVICEREMOVECOMPLETE) {
        UpdateUSBDisplay();
    }
    return 0;
}

void CUSBKeyMakerDlg::OnBnClickedRadioUnlimit() {
    m_radioUnlimit.SetCheck(BST_CHECKED);
    m_radioLimit.SetCheck(BST_UNCHECKED);

    SYSTEMTIME unlimitedTime = { 9999, 12, 0, 31, 0, 0, 0, 0 };
    m_datePicker.SetTime(&unlimitedTime);
    m_datePicker.EnableWindow(FALSE);
}

void CUSBKeyMakerDlg::OnBnClickedRadioLimit() {
    m_radioLimit.SetCheck(BST_CHECKED);
    m_radioUnlimit.SetCheck(BST_UNCHECKED);

    CTime currentTime = CTime::GetCurrentTime();
    SYSTEMTIME systemTime;
    currentTime.GetAsSystemTime(systemTime);

    m_datePicker.SetTime(&systemTime);
    m_datePicker.EnableWindow(TRUE);
}

void CUSBKeyMakerDlg::OnBnClickedCheckAllOptions() {
    BOOL bCheckAll = m_checkAllOptions.GetCheck() == BST_CHECKED;

    for (auto& checkBox : m_checkOptions) {
        checkBox.SetCheck(bCheckAll ? BST_CHECKED : BST_UNCHECKED);
        checkBox.EnableWindow(!bCheckAll); 
    }
}

void CUSBKeyMakerDlg::OnBnClickedButtonKeyMake()
{
    
    // 선택된 USB 확인
    CString logMessage;
    for (int i = 0; i < m_checkDrives.size(); i++) {
        if (m_checkDrives[i].GetCheck() == BST_CHECKED) {
            CString usbName;
            m_checkDrives[i].GetWindowText(usbName);

            // 만료일자 설정
            COleDateTime expiryDate;
            m_datePicker.GetTime(expiryDate);
            string expireDateString = CT2A(expiryDate.Format(_T("%Y%m%d")));

            // 모듈 타입 설정
            unsigned int moduleType = 0;
            for (int j = 0; j < m_checkOptions.size(); ++j) {
                if (m_checkOptions[j].GetCheck() == BST_CHECKED) {
                    moduleType += (1 << j);
                }
            }

            // USBKeyCryptoValidator 호출
            EncryptResult result = UsbKeyEncrypt(string(CT2A(usbName)),
                expireDateString,
                moduleType);

            // 결과 로그 처리
            COleDateTime currentTime = COleDateTime::GetCurrentTime();
            CString currentTimeString = currentTime.Format(_T("%Y-%m-%d %H:%M:%S"));

            logMessage.Format(_T("[%s], USB S/N: %s, 만료일: %s, 호환 모듈 타입: 0x%X, 결과: %s\n"),
                currentTimeString,                        // 현재 시간
                CString(result.serialNumber.c_str()),    // USB 시리얼 넘버
                CString(expireDateString.c_str()),      // 만료일자
                moduleType,                            // 모듈 타입 (16진수로 표시)
                result.errorCode == EncryptResult::ENCRYPT_SUCCESS ? _T("성공") : _T("실패")); // 결과

            // 로그 출력
            m_listLog.AddString(logMessage);

            // 로그 저장
            SaveLogToFile(logMessage);
        }
    }
}

void CUSBKeyMakerDlg::SaveLogToFile(const CString& logMessage)
{
    // 로그 파일로 저장
    CStdioFile logFile;
    CFileException ex;

    if (logFile.Open(_T("USBKeyMaker.log"), CFile::modeCreate | CFile::modeNoTruncate | CFile::modeWrite | CFile::typeBinary, &ex)) {
        if (logFile.GetLength() == 0) {
            BYTE bom[] = { 0xEF, 0xBB, 0xBF }; // UTF-8 BOM
            logFile.Write(bom, sizeof(bom));
        }

        // CString -> UTF-8 변환
        CT2A utf8Message(logMessage, CP_UTF8); 
        logFile.SeekToEnd();
        logFile.Write(utf8Message, strlen(utf8Message)); // 바이너리 쓰기
        logFile.Close();
    }
    else {
        CString errorMessage;
        errorMessage.Format(_T("로그 파일을 열 수 없습니다. 오류 코드: %d"), ex.m_cause);
        AfxMessageBox(errorMessage);
    }
}


void CUSBKeyMakerDlg::OnDestroy() {
    if (m_hDeviceNotify) {
        UnregisterDeviceNotification(m_hDeviceNotify);
        m_hDeviceNotify = NULL;
    }
    CDialogEx::OnDestroy();
}
