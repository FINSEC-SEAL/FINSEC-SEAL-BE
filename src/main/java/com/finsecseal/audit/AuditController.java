package com.finsecseal.audit;

import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import java.util.List;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/audit-records")
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping
    ApiResponse<List<AuditDto.Record>> find(
            @RequestParam String resourceType,
            @RequestParam UUID resourceId,
            @RequestParam(defaultValue = "25") int limit
    ) {
        return ApiResponse.success(
                auditService.find(resourceType, resourceId, limit),
                TraceIdFilter.currentTraceId()
        );
    }
}
