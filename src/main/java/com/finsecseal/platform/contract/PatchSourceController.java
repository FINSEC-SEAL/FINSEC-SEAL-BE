package com.finsecseal.platform.contract;
import com.finsecseal.common.api.ApiResponse;
import com.finsecseal.common.api.TraceIdFilter;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/v1/platform/patch-sources")
public class PatchSourceController {
    private final PatchSourceService service;
    public PatchSourceController(PatchSourceService service) {this.service=service;}
    @GetMapping("/{findingId}")
    ApiResponse<PatchSourceService.PatchSource> find(@PathVariable UUID findingId,HttpServletRequest r) {
        return ApiResponse.success(service.find(findingId,ContractController.reviewer(r)),TraceIdFilter.currentTraceId());
    }
}
