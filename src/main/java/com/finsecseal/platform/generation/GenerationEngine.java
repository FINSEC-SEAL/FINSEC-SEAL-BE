package com.finsecseal.platform.generation;

import com.finsecseal.platform.generation.GenerationContract.*;

public interface GenerationEngine {
    boolean available(Kind kind);
    Generated generate(Work work);
}
