package com.yourco.batch.job;

import org.springframework.batch.core.Job;
import org.springframework.batch.core.Step;
import org.springframework.batch.core.job.builder.JobBuilder;
import org.springframework.batch.core.repository.JobRepository;
import org.springframework.batch.core.step.builder.StepBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * サンプル Spring Batch Job
 * - 実案件では「冪等性キー」「再実行」「ロールバック単位」を設計書で必ず定義してください。
 */
@Configuration
public class SampleJobConfig {

  @Bean
  Job sampleJob(JobRepository jobRepository, Step sampleStep) {
    return new JobBuilder("sampleJob", jobRepository)
        .start(sampleStep)
        .build();
  }

  @Bean
  Step sampleStep(JobRepository jobRepository, PlatformTransactionManager tx) {
    return new StepBuilder("sampleStep", jobRepository)
        .tasklet((contribution, chunkContext) -> {
          System.out.println("Sample batch step executed.");
          return org.springframework.batch.repeat.RepeatStatus.FINISHED;
        }, tx)
        .build();
  }
}
