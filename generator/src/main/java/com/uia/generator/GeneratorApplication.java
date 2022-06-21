package com.uia.generator;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.extension.service.IService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.baomidou.mybatisplus.generator.FastAutoGenerator;
import com.baomidou.mybatisplus.generator.config.DataSourceConfig;
import com.baomidou.mybatisplus.generator.config.GlobalConfig;
import com.baomidou.mybatisplus.generator.config.PackageConfig;
import com.baomidou.mybatisplus.generator.config.StrategyConfig;
import com.baomidou.mybatisplus.generator.config.querys.MySqlQuery;
import com.baomidou.mybatisplus.generator.config.rules.NamingStrategy;
import com.baomidou.mybatisplus.generator.engine.VelocityTemplateEngine;
import com.baomidou.mybatisplus.generator.fill.Column;
import com.baomidou.mybatisplus.generator.fill.Property;
/**
 * @ClassName: {@link GeneratorApplication}
 * @Author AbelEthan
 * @Email AbelEthan@126.com
 * @Date 2022/6/9 下午5:30
 * @Description
 */
public class GeneratorApplication {

    /**
     * 数据库配置
     *
     * @return
     */
    private static DataSourceConfig.Builder dataSourceConfigBuilder() {
        return new DataSourceConfig.Builder("jdbc:mysql://39.100.229.199:3308/uia", "hjeduadmin", "SuperhjEdu@2020")
                .dbQuery(new MySqlQuery())
                ;
    }

    /**
     * 全局配置
     *
     * @param builder
     */
    private static void globalConfig(GlobalConfig.Builder builder) {
        builder
                .outputDir("/home/abelethan/IdeaProjects/uia-platform/generator/src/main/java")
                .author("AbelEthan")
                .enableSwagger()
                .commentDate("yyyy-MM-dd HH:mm:ss")
        ;
    }

    /**
     * 包配置
     *
     * @param builder
     */
    private static void packageConfig(PackageConfig.Builder builder) {
        builder.parent("com.uia") // 设置父包名
                .moduleName("authorization") // 设置父包模块名
                .entity("entity")
                .service("service")
                .serviceImpl("service.impl")
                .mapper("mapper")
                .xml("mappers")
                .controller("web")
                .other("api");
    }

    private static void strategyConfig(StrategyConfig.Builder builder) {
        // 设置需要生成的表名
        builder
                .addInclude("oauth2_user")
                .entityBuilder()
                .enableTableFieldAnnotation()
                .enableLombok()
                .naming(NamingStrategy.underline_to_camel)
                .addSuperEntityColumns("create_time", "update_time")
                .addTableFills(new Column("create_time", FieldFill.INSERT))
                .addTableFills(new Property("updateTime", FieldFill.INSERT_UPDATE))
                .idType(IdType.AUTO)
                .formatFileName("%s")
                .build()
                .controllerBuilder()
                .enableRestStyle()
                .formatFileName("%sController")
                .fileOverride()
                .build()
                .serviceBuilder()
                .superServiceClass(IService.class)
                .superServiceImplClass(ServiceImpl.class)
                .formatServiceFileName("%sService")
                .formatServiceImplFileName("%sServiceImp")
                .fileOverride()
                .build()
                .mapperBuilder()
                .enableBaseResultMap()
                .superClass(BaseMapper.class)
                .formatMapperFileName("%sMapper")
                .formatXmlFileName("%sMapper")
                .fileOverride()
                .build();
    }

    public static void main(String[] args) {
        FastAutoGenerator
                .create(dataSourceConfigBuilder())
                .globalConfig(builder -> {
                    globalConfig(builder);
                })
                .packageConfig(builder -> {
                    packageConfig(builder);
                })
                .strategyConfig(builder -> {
                    strategyConfig(builder);
                })
                .templateEngine(new VelocityTemplateEngine())
                .execute();
    }
}
