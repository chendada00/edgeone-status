import express from 'express';
import 'dotenv/config';
// import { fileURLToPath } from 'url';
import { teo } from "tencentcloud-sdk-nodejs-teo";
import { CommonClient } from "tencentcloud-sdk-nodejs-common";

// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);

const app = express();

// Function to read keys
function getKeys() {
    return {
        secretId: process.env.SECRET_ID,
        secretKey: process.env.SECRET_KEY
    };
}

// Metrics that belong to DescribeTimingL7OriginPullData
const ORIGIN_PULL_METRICS = [
    'l7Flow_outFlux_hy',
    'l7Flow_outBandwidth_hy',
    'l7Flow_request_hy',
    'l7Flow_inFlux_hy',
    'l7Flow_inBandwidth_hy'
];

// Metrics that belong to DescribeTopL7AnalysisData
const TOP_ANALYSIS_METRICS = [
    'l7Flow_outFlux_country',
    'l7Flow_outFlux_province',
    'l7Flow_outFlux_statusCode',
    'l7Flow_outFlux_domain',
    'l7Flow_outFlux_url',
    'l7Flow_outFlux_resourceType',
    'l7Flow_outFlux_sip',
    'l7Flow_outFlux_referers',
    'l7Flow_outFlux_ua_device',
    'l7Flow_outFlux_ua_browser',
    'l7Flow_outFlux_ua_os',
    'l7Flow_outFlux_ua',
    'l7Flow_request_country',
    'l7Flow_request_province',
    'l7Flow_request_statusCode',
    'l7Flow_request_domain',
    'l7Flow_request_url',
    'l7Flow_request_resourceType',
    'l7Flow_request_sip',
    'l7Flow_request_referers',
    'l7Flow_request_ua_device',
    'l7Flow_request_ua_browser',
    'l7Flow_request_ua_os',
    'l7Flow_request_ua'
];

// Metrics that belong to DescribeWebProtectionData (DDoS/Security)
const SECURITY_METRICS = [
    'ccAcl_interceptNum',
    'ccManage_interceptNum',
    'ccRate_interceptNum'
];

// Metrics that belong to DescribeTimingFunctionAnalysisData (Edge Functions)
const FUNCTION_METRICS = [
    'function_requestCount',
    'function_cpuCostTime'
];

function parseBlacklist(rawValue) {
    if (!rawValue) return [];

    try {
        const parsed = JSON.parse(rawValue);
        if (Array.isArray(parsed)) {
            return parsed
                .map(item => String(item || '').trim().toLowerCase())
                .filter(Boolean);
        }
    } catch (err) {
        // Fallback for comma/newline separated values.
    }

    return rawValue
        .split(/[\n,]/)
        .map(item => item.trim().toLowerCase())
        .filter(Boolean);
}

function normalizeHost(value) {
    return String(value || '').trim().toLowerCase();
}

function extractHostname(value) {
    const normalized = normalizeHost(value).replace(/^`+|`+$/g, '');
    if (!normalized || normalized === '-') return '';

    if (/^https?:\/\//i.test(normalized)) {
        try {
            return new URL(normalized).hostname.toLowerCase();
        } catch (err) {
            return normalized;
        }
    }

    return normalized.split('/')[0].split(':')[0];
}

function createBlacklistSet() {
    return new Set(parseBlacklist(process.env.BLACK_LIST));
}

function isBlacklistedHost(host, blacklistSet = createBlacklistSet()) {
    return blacklistSet.has(extractHostname(host));
}

function filterDetailDataByBlacklist(metric, detailData, blacklistSet = createBlacklistSet()) {
    if (!Array.isArray(detailData) || blacklistSet.size === 0) return detailData;

    const shouldFilter = metric.includes('_domain') || metric.includes('_url') || metric.includes('_referers');
    if (!shouldFilter) return detailData;

    return detailData.filter(item => !isBlacklistedHost(item?.Key, blacklistSet));
}

function filterApiResponseData(metric, data, blacklistSet = createBlacklistSet()) {
    if (!data || blacklistSet.size === 0 || !Array.isArray(data.Data)) return data;

    data.Data = data.Data.map(item => {
        if (Array.isArray(item?.DetailData)) {
            return {
                ...item,
                DetailData: filterDetailDataByBlacklist(metric, item.DetailData, blacklistSet)
            };
        }
        if (Array.isArray(item?.Data)) {
            return {
                ...item,
                Data: filterDetailDataByBlacklist(metric, item.Data, blacklistSet)
            };
        }
        return item;
    });

    return data;
}

app.get('/config', (req, res) => {
    const blackList = parseBlacklist(process.env.BLACK_LIST);
    res.json({
        siteName: process.env.SITE_NAME || '伴随流量分析',
        siteIcon: process.env.SITE_ICON || '/favicon.png',
        icp: process.env.ICP || '陕ICP备2024028531号',
        blackList
    });
});

app.get('/zones', async (req, res) => {
    try {
        const { secretId, secretKey } = getKeys();
        const blacklistSet = createBlacklistSet();
        
        if (!secretId || !secretKey) {
            return res.status(500).json({ error: "Missing credentials" });
        }

        const TeoClient = teo.v20220901.Client;
        const clientConfig = {
            credential: {
                secretId: secretId,
                secretKey: secretKey,
            },
            region: "ap-guangzhou",
            profile: {
                httpProfile: {
                    endpoint: "teo.tencentcloudapi.com",
                },
            },
        };

        const client = new TeoClient(clientConfig);
        const params = {};
        
        console.log("Calling DescribeZones...");
        const data = await client.DescribeZones(params);
        if (Array.isArray(data?.Zones) && blacklistSet.size > 0) {
            data.Zones = data.Zones.filter(zone => !isBlacklistedHost(zone?.ZoneName, blacklistSet));
        }
        res.json(data);
    } catch (err) {
        console.error("Error calling DescribeZones:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/pages/build-count', async (req, res) => {
    try {
        const { secretId, secretKey } = getKeys();
        
        if (!secretId || !secretKey) {
            return res.status(500).json({ error: "Missing credentials" });
        }

        const commonClientConfig = {
            credential: {
                secretId: secretId,
                secretKey: secretKey,
            },
            region: "ap-guangzhou",
            profile: {
                httpProfile: {
                    endpoint: "teo.tencentcloudapi.com",
                },
            },
        };

        const client = new CommonClient(
            "teo.tencentcloudapi.com",
            "2022-09-01",
            commonClientConfig
        );

        // 1. Find ZoneId (Pages usually requires 'default-pages-zone')
        let targetZoneId = req.query.zoneId;

        if (!targetZoneId) {
             try {
                const TeoClient = teo.v20220901.Client;
                const teoClient = new TeoClient({
                    credential: { secretId, secretKey },
                    region: "ap-guangzhou",
                    profile: { httpProfile: { endpoint: "teo.tencentcloudapi.com" } }
                });
                
                const zonesData = await teoClient.DescribeZones({});
                if (zonesData && zonesData.Zones) {
                    const pagesZone = zonesData.Zones.find(z => z.ZoneName === 'default-pages-zone');
                    if (pagesZone) {
                        targetZoneId = pagesZone.ZoneId;
                        console.log(`Found default-pages-zone: ${targetZoneId}`);
                    } else if (zonesData.Zones.length > 0) {
                        targetZoneId = zonesData.Zones[0].ZoneId;
                        console.log(`default-pages-zone not found, using first zone: ${targetZoneId}`);
                    }
                }
             } catch (zErr) {
                 console.error("Error fetching zones for Pages:", zErr);
             }
        }

        if (!targetZoneId) {
            return res.status(400).json({ error: "Missing ZoneId and could not auto-discover one." });
        }

        const params = {
            "Interface": "pages:DescribePagesDeploymentUsage",
            "Payload": "{}",
            "ZoneId": targetZoneId
        };
        
        console.log("Calling DescribePagesResources with params:", JSON.stringify(params));
        const data = await client.request("DescribePagesResources", params);
        
        // Parse Result string if present
        if (data && data.Result) {
            try {
                data.parsedResult = JSON.parse(data.Result);
            } catch (e) {
                console.error("Error parsing Result JSON:", e);
            }
        }
        
        res.json(data);
    } catch (err) {
        console.error("Error calling DescribePagesResources:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/pages/cloud-function-requests', async (req, res) => {
    try {
        const { secretId, secretKey } = getKeys();
        
        if (!secretId || !secretKey) {
            return res.status(500).json({ error: "Missing credentials" });
        }

        const commonClientConfig = {
            credential: {
                secretId: secretId,
                secretKey: secretKey,
            },
            region: "ap-guangzhou",
            profile: {
                httpProfile: {
                    endpoint: "teo.tencentcloudapi.com",
                },
            },
        };

        const client = new CommonClient(
            "teo.tencentcloudapi.com",
            "2022-09-01",
            commonClientConfig
        );

        // 1. Find ZoneId
        let targetZoneId = req.query.zoneId;
        const { startTime, endTime } = req.query;

        if (!targetZoneId) {
             try {
                const TeoClient = teo.v20220901.Client;
                const teoClient = new TeoClient({
                    credential: { secretId, secretKey },
                    region: "ap-guangzhou",
                    profile: { httpProfile: { endpoint: "teo.tencentcloudapi.com" } }
                });
                
                const zonesData = await teoClient.DescribeZones({});
                if (zonesData && zonesData.Zones) {
                    const pagesZone = zonesData.Zones.find(z => z.ZoneName === 'default-pages-zone');
                    if (pagesZone) {
                        targetZoneId = pagesZone.ZoneId;
                        console.log(`Found default-pages-zone: ${targetZoneId}`);
                    } else if (zonesData.Zones.length > 0) {
                        targetZoneId = zonesData.Zones[0].ZoneId;
                        console.log(`default-pages-zone not found, using first zone: ${targetZoneId}`);
                    }
                }
             } catch (zErr) {
                 console.error("Error fetching zones for Pages:", zErr);
             }
        }

        if (!targetZoneId) {
            return res.status(400).json({ error: "Missing ZoneId and could not auto-discover one." });
        }

        const payload = {
            ZoneId: targetZoneId,
            Interval: "hour"
        };
        
        if (startTime) payload.StartTime = startTime;
        if (endTime) payload.EndTime = endTime;

        const params = {
            "ZoneId": targetZoneId,
            "Interface": "pages:DescribePagesFunctionsRequestDataByZone",
            "Payload": JSON.stringify(payload)
        };
        
        console.log("Calling DescribePagesResources (CloudFunction) with params:", JSON.stringify(params));
        const data = await client.request("DescribePagesResources", params);
        
        // Parse Result string if present
        if (data && data.Result) {
            try {
                data.parsedResult = JSON.parse(data.Result);
            } catch (e) {
                console.error("Error parsing Result JSON:", e);
            }
        }
        
        res.json(data);
    } catch (err) {
        console.error("Error calling DescribePagesResources for CloudFunction:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/pages/cloud-function-monthly-stats', async (req, res) => {
    try {
        const { secretId, secretKey } = getKeys();
        
        if (!secretId || !secretKey) {
            return res.status(500).json({ error: "Missing credentials" });
        }

        const commonClientConfig = {
            credential: {
                secretId: secretId,
                secretKey: secretKey,
            },
            region: "ap-guangzhou",
            profile: {
                httpProfile: {
                    endpoint: "teo.tencentcloudapi.com",
                },
            },
        };

        const client = new CommonClient(
            "teo.tencentcloudapi.com",
            "2022-09-01",
            commonClientConfig
        );

        // 1. Find ZoneId
        let targetZoneId = req.query.zoneId;

        if (!targetZoneId) {
             try {
                const TeoClient = teo.v20220901.Client;
                const teoClient = new TeoClient({
                    credential: { secretId, secretKey },
                    region: "ap-guangzhou",
                    profile: { httpProfile: { endpoint: "teo.tencentcloudapi.com" } }
                });
                
                const zonesData = await teoClient.DescribeZones({});
                if (zonesData && zonesData.Zones) {
                    const pagesZone = zonesData.Zones.find(z => z.ZoneName === 'default-pages-zone');
                    if (pagesZone) {
                        targetZoneId = pagesZone.ZoneId;
                        console.log(`Found default-pages-zone: ${targetZoneId}`);
                    } else if (zonesData.Zones.length > 0) {
                        targetZoneId = zonesData.Zones[0].ZoneId;
                        console.log(`default-pages-zone not found, using first zone: ${targetZoneId}`);
                    }
                }
             } catch (zErr) {
                 console.error("Error fetching zones for Pages:", zErr);
             }
        }

        if (!targetZoneId) {
            return res.status(400).json({ error: "Missing ZoneId and could not auto-discover one." });
        }

        const payload = {
            ZoneId: targetZoneId,
        };

        const params = {
            "ZoneId": targetZoneId,
            "Interface": "pages:DescribeHistoryCloudFunctionStats",
            "Payload": JSON.stringify(payload)
        };
        
        console.log("Calling DescribePagesResources (CloudFunction Monthly) with params:", JSON.stringify(params));
        const data = await client.request("DescribePagesResources", params);
        
        // Parse Result string if present
        if (data && data.Result) {
            try {
                data.parsedResult = JSON.parse(data.Result);
            } catch (e) {
                console.error("Error parsing Result JSON:", e);
            }
        }
        
        res.json(data);
    } catch (err) {
        console.error("Error calling DescribePagesResources for CloudFunction Monthly:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/traffic', async (req, res) => {
    try {
        const { secretId, secretKey } = getKeys();
        const blacklistSet = createBlacklistSet();
        
        if (!secretId || !secretKey) {
            return res.status(500).json({ error: "Missing credentials" });
        }

        const TeoClient = teo.v20220901.Client;
        const clientConfig = {
            credential: {
                secretId: secretId,
                secretKey: secretKey,
            },
            region: "ap-guangzhou",
            profile: {
                httpProfile: {
                    endpoint: "teo.tencentcloudapi.com",
                },
            },
        };

        const client = new TeoClient(clientConfig);
        
        const now = new Date();
        const formatDate = (date) => {
             return date.toISOString().slice(0, 19) + 'Z';
        };

        const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        const metric = req.query.metric || "l7Flow_flux";
        const startTime = req.query.startTime || formatDate(yesterday);
        const endTime = req.query.endTime || formatDate(now);
        const interval = req.query.interval;
        const zoneId = req.query.zoneId;
        const zoneIds = zoneId ? [ zoneId ] : [ "*" ];
        const host = req.query.host;
        if (host && host !== '*' && isBlacklistedHost(host, blacklistSet)) {
            return res.status(403).json({ error: "Requested host is blocked by BLACK_LIST" });
        }
        const hosts = host && host !== '*' ? [ host ] : null;

        let params = {};
        let data;

        console.log(`Requesting metric: ${metric}, StartTime: ${startTime}, EndTime: ${endTime}, Interval: ${interval}`);

        if (TOP_ANALYSIS_METRICS.includes(metric)) {
            // API: DescribeTopL7AnalysisData
            params = {
                "StartTime": startTime,
                "EndTime": endTime,
                "MetricName": metric,
                "ZoneIds": zoneIds
            };
            // 使用 Filters 参数过滤域名，参考 get.php
            if (hosts) {
                params["Filters"] = [
                    {
                        "Key": "domain",
                        "Operator": "equals",
                        "Value": hosts
                    }
                ];
            }
            console.log("Calling DescribeTopL7AnalysisData with params:", JSON.stringify(params, null, 2));
            data = await client.DescribeTopL7AnalysisData(params);
        } else if (SECURITY_METRICS.includes(metric)) {
            // API: DescribeWebProtectionData (DDoS) using CommonClient
            // 注意：DescribeWebProtectionData 不支持按域名过滤，只能按 Zone 过滤
            params = {
                "StartTime": startTime,
                "EndTime": endTime,
                "MetricNames": [ metric ],
                "ZoneIds": zoneIds
            };

            if (interval && interval !== 'auto') {
                params["Interval"] = interval;
            }
            
            // CommonClient setup
            const commonClientConfig = {
                credential: {
                    secretId: secretId,
                    secretKey: secretKey,
                },
                region: "ap-guangzhou",
                profile: {
                    httpProfile: {
                        endpoint: "teo.tencentcloudapi.com",
                    },
                },
            };

            const commonClient = new CommonClient(
                "teo.tencentcloudapi.com",
                "2022-09-01",
                commonClientConfig
            );

            console.log("Calling DescribeWebProtectionData with params:", JSON.stringify(params, null, 2));
            data = await commonClient.request("DescribeWebProtectionData", params);
            
        } else if (FUNCTION_METRICS.includes(metric)) {
            // API: DescribeTimingFunctionAnalysisData (Edge Functions)
            let metricNames = [metric];
            if (metric === 'function_cpuCostTime') {
                metricNames = ["function_requestCount", "function_cpuCostTime"];
            }

            params = {
                "StartTime": startTime,
                "EndTime": endTime,
                "MetricNames": metricNames,
                "ZoneIds": zoneIds
            };

            if (interval && interval !== 'auto') {
                params["Interval"] = interval;
            }
            
            // 使用 Filters 参数过滤域名，参考 get.php
            if (hosts) {
                params["Filters"] = [
                    {
                        "Key": "domain",
                        "Operator": "equals",
                        "Value": hosts
                    }
                ];
            }

            console.log("Calling DescribeTimingFunctionAnalysisData with params:", JSON.stringify(params, null, 2));
            
            // Use CommonClient for DescribeTimingFunctionAnalysisData
            const commonClientConfig = {
                credential: {
                    secretId: secretId,
                    secretKey: secretKey,
                },
                region: "ap-guangzhou",
                profile: {
                    httpProfile: {
                        endpoint: "teo.tencentcloudapi.com",
                    },
                },
            };

            const commonClient = new CommonClient(
                "teo.tencentcloudapi.com",
                "2022-09-01",
                commonClientConfig
            );

            data = await commonClient.request("DescribeTimingFunctionAnalysisData", params);

        } else {
            // API: DescribeTimingL7AnalysisData OR DescribeTimingL7OriginPullData
            // 参考 get.php，使用 Filters 参数过滤域名
            params = {
                "StartTime": startTime,
                "EndTime": endTime,
                "MetricNames": [ metric ],
                "ZoneIds": zoneIds
            };

            if (interval && interval !== 'auto') {
                params["Interval"] = interval;
            }
            
            // 使用 Filters 参数过滤域名，参考 get.php
            if (hosts) {
                params["Filters"] = [
                    {
                        "Key": "domain",
                        "Operator": "equals",
                        "Value": hosts
                    }
                ];
            }
            
            console.log("Calling Timing API with params:", JSON.stringify(params, null, 2));
            
            if (ORIGIN_PULL_METRICS.includes(metric)) {
                data = await client.DescribeTimingL7OriginPullData(params);
            } else {
                data = await client.DescribeTimingL7AnalysisData(params);
            }
        }
        
        res.json(filterApiResponseData(metric, data, blacklistSet));
    } catch (err) {
        console.error("Error calling Tencent Cloud API:", err);
        res.status(500).json({ error: err.message });
    }
});

// 获取子域名列表 - 使用DescribeTopL7AnalysisData获取域名列表
app.get('/hosts', async (req, res) => {
    try {
        const { secretId, secretKey } = getKeys();
        const blacklistSet = createBlacklistSet();
        
        if (!secretId || !secretKey) {
            return res.status(500).json({ error: "Missing credentials" });
        }

        const zoneId = req.query.zoneId;
        if (!zoneId || zoneId === '*') {
            return res.json({ Hosts: [] });
        }

        // 使用 CommonClient 调用 DescribeTopL7AnalysisData 获取域名列表
        const commonClientConfig = {
            credential: {
                secretId: secretId,
                secretKey: secretKey,
            },
            region: "ap-guangzhou",
            profile: {
                httpProfile: {
                    endpoint: "teo.tencentcloudapi.com",
                },
            },
        };

        const commonClient = new CommonClient(
            "teo.tencentcloudapi.com",
            "2022-09-01",
            commonClientConfig
        );

        // 获取最近7天的数据，按域名分组
        const now = new Date();
        const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        const formatDate = (date) => date.toISOString().slice(0, 19) + 'Z';

        const params = {
            "StartTime": formatDate(sevenDaysAgo),
            "EndTime": formatDate(now),
            "MetricName": "l7Flow_outFlux_domain",
            "ZoneIds": [zoneId],
            "Limit": 1000
        };
        
        console.log("Calling DescribeTopL7AnalysisData for zone:", zoneId);
        const data = await commonClient.request("DescribeTopL7AnalysisData", params);
        
        console.log("API Response keys:", Object.keys(data));
        console.log("API Response:", JSON.stringify(data, null, 2));
        
        // 从返回数据中提取域名列表 - DescribeTopL7AnalysisData 返回结构是 Data[0].DetailData
        let hosts = [];
        
        // 数据结构: { Data: [{ DetailData: [{ Key: "domain", Value: ... }] }] }
        const topData = data.Data || data.Response?.Data;
        if (Array.isArray(topData) && topData.length > 0) {
            const detailData = topData[0].DetailData || topData[0].Data;
            if (Array.isArray(detailData)) {
                hosts = detailData.map(item => ({
                    Host: item.Key || item.Domain || item.Host || ''
                })).filter(h => h.Host);
            }
        }
        
        // 去重
        const uniqueHosts = [];
        const seen = new Set();
        for (const host of hosts) {
            if (!seen.has(host.Host) && !isBlacklistedHost(host.Host, blacklistSet)) {
                seen.add(host.Host);
                uniqueHosts.push(host);
            }
        }
        
        const response = { Hosts: uniqueHosts };
        console.log("Response to client:", JSON.stringify(response));
        res.json(response);
    } catch (err) {
        console.error("Error calling DescribeTopL7AnalysisData:", err);
        console.error("Error details:", JSON.stringify(err, null, 2));
        res.status(500).json({ error: err.message || String(err) });
    }
});

export default app;
