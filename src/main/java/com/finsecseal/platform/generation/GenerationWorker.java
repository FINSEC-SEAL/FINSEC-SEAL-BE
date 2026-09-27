package com.finsecseal.platform.generation;

import com.finsecseal.common.api.BusinessException;
import com.finsecseal.contract.*;
import jakarta.annotation.PreDestroy;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class GenerationWorker {
    private final GenerationOperationService operations;
    private final GenerationEngine engine;
    private final boolean enabled;
    private final AtomicBoolean busy=new AtomicBoolean();
    private final ExecutorService executor=Executors.newSingleThreadExecutor(r->{Thread thread=new Thread(r,"contract-generation");thread.setDaemon(true);return thread;});
    public GenerationWorker(GenerationOperationService operations,GenerationEngine engine,
            @Value("${finsec.generation.worker-enabled:true}") boolean enabled) {
        this.operations=operations;this.engine=engine;this.enabled=enabled;
    }
    @Scheduled(fixedDelayString="${finsec.generation.poll-ms:1000}")
    public void poll() {
        if(!enabled) return;
        operations.expire();
        if(busy.compareAndSet(false,true)) {
            try {executor.execute(()->{try{runOne();}finally{busy.set(false);}});}
            catch(RejectedExecutionException exception) {busy.set(false);}
        }
    }
    /** No transaction here. Claim, source checks and completion each finish before the next phase. */
    public boolean runOne() {
        var next=operations.claim();
        if(next.isEmpty()) return false;
        var work=next.orElseThrow();String stage="SOURCE";
        try {
            operations.checkBeforeModel(work);
            if(!engine.available(work.kind())) {
                operations.fail(work,"GENERATION_DISABLED","PROVIDER");return true;
            }
            stage="GENERATION";
            var result=engine.generate(work);
            stage="PERSISTENCE";
            operations.complete(work,result);
        } catch(RuntimeException exception) {
            operations.fail(work,code(exception),stage);
        }
        return true;
    }
    private String code(RuntimeException exception) {
        if(exception instanceof BusinessException e) return e.errorCode().name();
        if(exception instanceof ContractCandidateGenerationService.CandidateGenerationException e) return e.code().name();
        if(exception instanceof SafetyContractPatchGenerationService.PatchGenerationException e) return e.code().name();
        if(exception instanceof SafetyContractGenerationSourceService.GenerationSourceException e) return e.code().name();
        if(exception instanceof SafetyContractPatchGenerationSourceService.PatchGenerationSourceException e) return e.code().name();
        if(exception instanceof SafetyContractCandidatePromptBuilder.CandidatePromptException e) return e.code().name();
        if(exception instanceof SafetyContractCandidateResponseProcessor.CandidateResponseException e) return e.code().name();
        if(exception instanceof SafetyContractPatchPromptBuilder.PatchPromptException e) return e.code().name();
        if(exception instanceof SafetyContractPatchResponseProcessor.PatchResponseException e) return e.code().name();
        return "GENERATION_INTERNAL_ERROR";
    }
    @PreDestroy public void shutdown() {executor.shutdownNow();}
}
