#pragma once
#include <string>
#include <array>
#include <Dbt.h>
#include <initguid.h>
#include "UsbKeyCryptoValidator.h"

using namespace std;
using namespace UsbKeyCryptoValidator;

DEFINE_GUID(GUID_DEVINTERFACE_USB_DEVICE,
    0xA5DCBF10L, 0x6530, 0x11D2, 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED);

#pragma comment(lib, "UsbKeyCryptoValidator.lib")


// CUSBKeyMakerDlg 대화 상자
class CUSBKeyMakerDlg : public CDialogEx {
public:
    CUSBKeyMakerDlg(CWnd* pParent = nullptr); // 표준 생성자입니다.

#ifdef AFX_DESIGN_TIME
    enum { IDD = IDD_USBKEYMAKER_DIALOG };
#endif

protected:
    virtual void DoDataExchange(CDataExchange* pDX); // DDX/DDV 지원입니다.
    virtual BOOL OnInitDialog();
    virtual void OnDestroy();
    afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
    afx_msg void OnPaint();
    afx_msg HCURSOR OnQueryDragIcon();
    DECLARE_MESSAGE_MAP()

private:
    HICON m_hIcon;
    CButton m_radioUnlimit;
    CButton m_radioLimit;
    CDateTimeCtrl m_datePicker;
    array<CButton, 5>  m_checkDrives;
    array<CButton, 12> m_checkOptions;
    CButton m_checkAllOptions;
    CListBox m_listLog;
    HDEVNOTIFY m_hDeviceNotify;

    void InitializeUSBDisplay();
    void UpdateUSBDisplay();
    void SaveLogToFile(const CString& logMessage);

    afx_msg LRESULT OnDeviceChange(WPARAM wParam, LPARAM lParam);
    afx_msg void OnBnClickedRadioUnlimit();
    afx_msg void OnBnClickedRadioLimit();
    afx_msg void OnBnClickedCheckAllOptions();
    afx_msg void OnBnClickedButtonKeyMake();

};
