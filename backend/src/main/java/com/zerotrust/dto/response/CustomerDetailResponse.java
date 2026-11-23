package com.zerotrust.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CustomerDetailResponse(
    CustomerResponse customer,
    List<AccountResponse> accounts
) {}
