import os
from typing import Any, Dict, List

from pydantic import SecretStr

import pytest

from langchain_community.tools.pangea.redact_guard import PangeaRedactGuard, PangeaConfig
from langchain_community.tools.pangea.domain_intel_guard import PangeaDomainIntelGuard, MaliciousDomainsError
from langchain_community.tools.pangea.ip_intel_guard import PangeaIpIntelGuard, MaliciousIpAddressesError
from langchain_community.tools.pangea.url_intel_guard import PangeaUrlIntelGuard, MaliciousUrlsError

try:
    from pangea.tools import (
        TestEnvironment,
        get_test_domain,
        get_test_token,
    )
except ImportError as e:
    raise ImportError(
        "Cannot import pangea, please install `pip install pangea-sdk==5.2.0b2`."
    ) from e

# Pangea Redact integration tests
@pytest.fixture()
def pangea_redact_guard() -> PangeaRedactGuard:
    env = TestEnvironment.DEVELOP
    config = PangeaConfig(domain=get_test_domain(env))
    return PangeaRedactGuard(pangea_token=SecretStr(get_test_token(env)), config=config)

# Run redact as a tool for agents
def test_redact_tool(pangea_redact_guard: PangeaRedactGuard) -> None:
    prompt = "My name is Dennis Nedry and my email is you.didnt.say.the.magic.word@gmail.com"
    expected = "My name is <PERSON> and my email is <EMAIL_ADDRESS>"
    response = pangea_redact_guard.run(prompt)
    assert response == expected, f"Erorr: {response}"

# Invoke redact as a runnable for chains
def test_redact_runnable(pangea_redact_guard: PangeaRedactGuard) -> None:
    prompt = "My name is Dennis Nedry and my email is you.didnt.say.the.magic.word@gmail.com"
    expected = "My name is <PERSON> and my email is <EMAIL_ADDRESS>"
    response = pangea_redact_guard.invoke(prompt)
    assert response == expected, f"Erorr: {response}"


# Pangea Domain Intel integration tests
@pytest.fixture()
def pangea_domain_intel_guard() -> PangeaDomainIntelGuard:
    env = TestEnvironment.DEVELOP
    config = PangeaConfig(domain=get_test_domain(env))
    return PangeaDomainIntelGuard(pangea_token=SecretStr(get_test_token(env)), config=config)

# Run domain as a tool for agents
def test_domain_intel_tool(pangea_domain_intel_guard: PangeaDomainIntelGuard) -> None:
    prompt = "Leave us a feedback here: http://737updatesboeing.com/feedback."
    with pytest.raises(MaliciousDomainsError, match="Malicious domains found in the provided input"):
        pangea_domain_intel_guard.run(prompt)

# Run domain as a runnable for chains
def test_domain_intel_runnable(pangea_domain_intel_guard: PangeaDomainIntelGuard) -> None:
    prompt = "Leave us a feedback here: http://737updatesboeing.com/feedback."
    with pytest.raises(MaliciousDomainsError, match="Malicious domains found in the provided input"):
        pangea_domain_intel_guard.invoke(prompt)

# Pangea IP Intel integration tests
@pytest.fixture()
def pangea_ip_intel_guard() -> PangeaIpIntelGuard:
    env = TestEnvironment.DEVELOP
    config = PangeaConfig(domain=get_test_domain(env))
    return PangeaIpIntelGuard(pangea_token=SecretStr(get_test_token(env)), config=config)

# Run IP as a tool for agents
def test_ip_intel_tool(pangea_ip_intel_guard: PangeaIpIntelGuard) -> None:
    prompt = "Please click here to confirm your order: http://113.235.101.11:54384/order/123."
    with pytest.raises(MaliciousIpAddressesError, match="Malicious IPs found in the provided input"):
        pangea_ip_intel_guard.run(prompt)

# Run IP as a runnable for chains
def test_ip_intel_runnable(pangea_ip_intel_guard: PangeaIpIntelGuard) -> None:
    prompt = "Please click here to confirm your order: http://113.235.101.11:54384/order/123."
    with pytest.raises(MaliciousIpAddressesError, match="Malicious IPs found in the provided input"):
        pangea_ip_intel_guard.invoke(prompt)

# Pangea URL Intel integration tests
@pytest.fixture()
def pangea_url_intel_guard() -> PangeaUrlIntelGuard:
    env = TestEnvironment.DEVELOP
    config = PangeaConfig(domain=get_test_domain(env))
    return PangeaUrlIntelGuard(pangea_token=SecretStr(get_test_token(env)), config=config)

# Run URL as a tool for agents
def test_url_intel_tool(pangea_url_intel_guard: PangeaUrlIntelGuard) -> None:
    prompt = "Summarize this: http://malware123.com/moreinfo"
    with pytest.raises(MaliciousUrlsError, match="Malicious URLs found in the provided input"):
        pangea_url_intel_guard.run(prompt)

# Run URL as a runnable for chains
def test_url_intel_runnable(pangea_url_intel_guard: PangeaUrlIntelGuard) -> None:
    prompt = "Summarize this: http://malware123.com/moreinfo"
    with pytest.raises(MaliciousUrlsError, match="Malicious URLs found in the provided input"):
        pangea_url_intel_guard.invoke(prompt)