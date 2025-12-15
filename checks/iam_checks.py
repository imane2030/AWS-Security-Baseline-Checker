"""IAM-related CIS benchmark checks."""

def get_all_checks(session):
    """Return list of all IAM checks."""
    return [
        lambda: check_root_account_mfa(session),
        lambda: check_root_account_usage(session),
        lambda: check_iam_users_mfa(session),
        lambda: check_unused_credentials(session),
        lambda: check_access_keys_rotation(session),
        lambda: check_password_policy(session),
        lambda: check_iam_policies_admin(session),
    ]


def check_root_account_mfa(session):
    """CIS 1.5: Ensure MFA is enabled for root account."""
    iam = session.client('iam')
    
    try:
        summary = iam.get_account_summary()['SummaryMap']
        root_mfa_enabled = summary.get('AccountMFAEnabled', 0) == 1
        
        return {
            'control_id': '1.5',
            'title': 'Ensure MFA is enabled for root account',
            'status': 'PASS' if root_mfa_enabled else 'FAIL',
            'severity': 'CRITICAL',
            'details': '' if root_mfa_enabled else 'Root account does not have MFA enabled',
            'remediation': 'Enable MFA for root account in AWS Console > IAM > Dashboard'
        }
    except Exception as e:
        return {
            'control_id': '1.5',
            'title': 'Ensure MFA is enabled for root account',
            'status': 'ERROR',
            'severity': 'CRITICAL',
            'details': str(e),
            'remediation': ''
        }


def check_root_account_usage(session):
    """CIS 1.7: Eliminate use of root account."""
    cloudtrail = session.client('cloudtrail')
    
    return {
        'control_id': '1.7',
        'title': 'Eliminate use of root account',
        'status': 'MANUAL',
        'severity': 'CRITICAL',
        'details': 'Manual review required - check CloudTrail for root account activity',
        'remediation': 'Create IAM users for daily operations and avoid using root account'
    }


def check_iam_users_mfa(session):
    """CIS 1.10: Ensure MFA is enabled for all IAM users with console password."""
    iam = session.client('iam')
    
    try:
        users_without_mfa = []
        paginator = iam.get_paginator('list_users')
        
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                
                # Check if user has console access
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except iam.exceptions.NoSuchEntityException:
                    has_console = False
                
                if has_console:
                    # Check MFA devices
                    mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                    if not mfa_devices:
                        users_without_mfa.append(username)
        
        status = 'PASS' if not users_without_mfa else 'FAIL'
        details = '' if not users_without_mfa else f'Users without MFA: {", ".join(users_without_mfa)}'
        
        return {
            'control_id': '1.10',
            'title': 'Ensure MFA is enabled for all IAM users with console password',
            'status': status,
            'severity': 'HIGH',
            'details': details,
            'remediation': 'Enable MFA for all console users in IAM > Users > Security credentials'
        }
    except Exception as e:
        return {
            'control_id': '1.10',
            'title': 'Ensure MFA is enabled for all IAM users with console password',
            'status': 'ERROR',
            'severity': 'HIGH',
            'details': str(e),
            'remediation': ''
        }


def check_unused_credentials(session):
    """CIS 1.12: Ensure credentials unused for 90 days or greater are disabled."""
    iam = session.client('iam')
    
    return {
        'control_id': '1.12',
        'title': 'Ensure credentials unused for 90 days are disabled',
        'status': 'MANUAL',
        'severity': 'MEDIUM',
        'details': 'Manual review required - check IAM credential report',
        'remediation': 'Disable or delete credentials unused for 90+ days'
    }


def check_access_keys_rotation(session):
    """CIS 1.14: Ensure access keys are rotated every 90 days."""
    return {
        'control_id': '1.14',
        'title': 'Ensure access keys are rotated every 90 days',
        'status': 'MANUAL',
        'severity': 'MEDIUM',
        'details': 'Manual review required - check IAM credential report',
        'remediation': 'Rotate access keys every 90 days'
    }


def check_password_policy(session):
    """CIS 1.8: Ensure IAM password policy requires strong passwords."""
    iam = session.client('iam')
    
    try:
        policy = iam.get_account_password_policy()['PasswordPolicy']
        
        checks = {
            'MinimumPasswordLength': policy.get('MinimumPasswordLength', 0) >= 14,
            'RequireUppercaseCharacters': policy.get('RequireUppercaseCharacters', False),
            'RequireLowercaseCharacters': policy.get('RequireLowercaseCharacters', False),
            'RequireNumbers': policy.get('RequireNumbers', False),
            'RequireSymbols': policy.get('RequireSymbols', False),
        }
        
        all_passed = all(checks.values())
        failed_checks = [k for k, v in checks.items() if not v]
        
        return {
            'control_id': '1.8',
            'title': 'Ensure IAM password policy requires strong passwords',
            'status': 'PASS' if all_passed else 'FAIL',
            'severity': 'MEDIUM',
            'details': '' if all_passed else f'Failed requirements: {", ".join(failed_checks)}',
            'remediation': 'Update password policy in IAM > Account settings'
        }
    except iam.exceptions.NoSuchEntityException:
        return {
            'control_id': '1.8',
            'title': 'Ensure IAM password policy requires strong passwords',
            'status': 'FAIL',
            'severity': 'MEDIUM',
            'details': 'No password policy configured',
            'remediation': 'Create password policy in
