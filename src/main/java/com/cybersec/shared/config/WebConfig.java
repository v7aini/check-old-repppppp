package com.cybersec.shared.config;
import com.cybersec.ids.controller.IdsInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.*;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    private final IdsInterceptor idsInterceptor;
    private final com.cybersec.ransomware.service.RansomwareInterceptor ransomwareInterceptor;

    @Autowired
    public WebConfig(IdsInterceptor idsInterceptor, com.cybersec.ransomware.service.RansomwareInterceptor ransomwareInterceptor) { 
        this.idsInterceptor = idsInterceptor;
        this.ransomwareInterceptor = ransomwareInterceptor;
    }


    @Override
    public void addInterceptors(InterceptorRegistry r) {
        r.addInterceptor(idsInterceptor).addPathPatterns("/**")
         .excludePathPatterns("/css/**","/js/**","/images/**","/favicon.ico","/ws/**","/h2-console/**");

        r.addInterceptor(ransomwareInterceptor).addPathPatterns("/**")
         .excludePathPatterns("/css/**","/js/**","/images/**","/favicon.ico","/ws/**","/h2-console/**");
    }

    @Bean public RestTemplate restTemplate() { return new RestTemplate(); }
}
