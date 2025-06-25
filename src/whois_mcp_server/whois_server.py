"""
Whois Analysis MCP Server
도메인/IP 대량 whois 분석을 위한 MCP 서버
"""

import asyncio
import httpx
import csv
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path
from mcp.server.fastmcp import FastMCP
import os
from dotenv import load_dotenv

load_dotenv()

# FastMCP 인스턴스 생성
mcp = FastMCP("Whois Analysis Server")

# API 서비스 키
SERVICE_KEY = os.getenv("WHOIS_SERVICE_KEY", "your_service_key_here")

@mcp.tool()
async def load_list_from_file(file_path: str, max_items: int = 1000000) -> Dict[str, Any]:
    """
    파일에서 도메인/IP 리스트를 로드합니다.
    
    Args:
        file_path: 도메인/IP 목록이 있는 파일 경로
        max_items: 최대 로드할 개수
    
    Returns:
        로드 결과 및 통계
    """
    try:
        if not Path(file_path).exists():
            return {
                "status": "error",
                "error": f"파일을 찾을 수 없습니다: {file_path}"
            }
        
        items = []
        with open(file_path, 'r') as f:
            for i, line in enumerate(f):
                if i >= max_items:
                    break
                item = line.strip()
                if item and not item.startswith('#'):
                    items.append(item)
        
        return {
            "status": "success",
            "loaded_count": len(items),
            "file_path": file_path,
            "preview": items[:10],
            "message": f"{len(items)}개 항목 로드 완료"
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": f"파일 로드 중 오류: {str(e)}"
        }



@mcp.tool()
async def lookup_whois(query: str, service_key: str = None) -> Dict[str, Any]:
    """
    도메인 또는 IP의 whois 정보를 조회합니다.
    
    Args:
        query: 조회할 도메인 또는 IP
        service_key: API 인증키 (선택사항)
    
    Returns:
        whois 정보
    """
    try:
        # 서비스 키 설정
        api_key = service_key or SERVICE_KEY
        if not api_key or api_key == "your_service_key_here":
            return {
                "query": query,
                "status": "error",
                "error": "API 서비스 키가 필요합니다."
            }
        
        # 쿼리 유형 판별 (IP or 도메인)
        is_ip = is_ip_address(query)
        
        # whois 정보 조회
        async with httpx.AsyncClient(timeout=10.0) as client:
            whois_data = await query_whois_api(client, query, api_key, is_ip)
            
        return {
            "query": query,
            "status": "success" if "error" not in whois_data else "error",
            "data": whois_data,
            "query_time": datetime.now().isoformat()
        }
        
    except Exception as e:
        import traceback
        return {
            "query": query,
            "status": "error",
            "error": f"API 호출 중 오류: {type(e).__name__}: {str(e)}\n{traceback.format_exc()}",
            "query_time": datetime.now().isoformat()
        }

@mcp.tool()
async def bulk_whois_lookup(items: List[str], batch_size: int = 100, delay: float = 0.1) -> Dict[str, Any]:
    """
    대량 도메인/IP 리스트의 whois 분석을 수행합니다.
    
    Args:
        items: 분석할 도메인/IP 목록
        batch_size: 배치당 처리할 개수
        delay: 배치 간 딜레이 (초)
    
    Returns:
        분석 결과 요약
    """
    try:
        total_items = len(items)
        processed = 0
        results = []
        errors = []
        
        # 배치 단위로 처리
        for i in range(0, total_items, batch_size):
            batch = items[i:i + batch_size]
            batch_results = await process_batch(batch)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    errors.append(str(result))
                elif result.get("status") == "success":
                    results.append(result)
                else:
                    errors.append(result.get("query", "unknown"))
            
            processed += len(batch)
            
            # 진행률 출력
            if processed % (batch_size * 10) == 0:
                print(f"진행률: {processed}/{total_items} ({processed/total_items*100:.1f}%)")
            
            # API 호출 제한을 위한 딜레이
            await asyncio.sleep(delay)
        
        return {
            "status": "completed",
            "total_items": total_items,
            "successful": len(results),
            "failed": len(errors),
            "success_rate": len(results) / total_items * 100 if total_items > 0 else 0,
            "results": results
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": f"대량 분석 중 오류: {str(e)}"
        }

async def process_batch(batch: List[str]) -> List[Dict[str, Any]]:
    """배치를 병렬로 처리"""
    tasks = [lookup_whois(item) for item in batch]
    return await asyncio.gather(*tasks, return_exceptions=True)

async def query_whois_api(client: httpx.AsyncClient, query: str, service_key: str, is_ip: bool = False) -> Dict[str, Any]:
    """
    whois API 호출 (IP/도메인에 따라 엔드포인트 및 파싱 분기)
    """
    try:
        params = {
            "serviceKey": service_key,
            "query": query,
            "answer": "xml"
        }
        
        if is_ip:
            url = "http://apis.data.go.kr/B551505/whois/ip_address"
        else:
            url = "http://apis.data.go.kr/B551505/whois/domain_name"
        
        response = await client.get(
            url,
            params=params
        )
        
        if response.status_code == 200:
            if is_ip:
                return parse_ip_whois_xml(response.text, query)
            else:
                return parse_domain_whois_xml(response.text, query)
        else:
            return {
                "error": f"API 호출 실패: HTTP {response.status_code}",
                "query": query
            }
            
    except Exception as e:
        import traceback
        return {
            "error": f"API 호출 중 오류: {type(e).__name__}: {str(e)}\n{traceback.format_exc()}",
            "query": query
        }

def parse_domain_whois_xml(xml_content: str, query: str) -> Dict[str, Any]:
    """
    도메인용 whois API XML 응답 파싱
    """
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_content)
        krdomain = root.find('./whois/krdomain')
        if krdomain is None:
            return {
                "error": "krdomain 태그를 찾을 수 없습니다.",
                "query": query
            }

        whois_data = {
            "query": query,
            "name": get_xml_text(krdomain, 'name'),
            "regName": get_xml_text(krdomain, 'regName'),
            "addr": get_xml_text(krdomain, 'addr'),
            "post": get_xml_text(krdomain, 'post'),
            "adminName": get_xml_text(krdomain, 'adminName'),
            "adminEmail": get_xml_text(krdomain, 'adminEmail'),
            "adminPhone": get_xml_text(krdomain, 'adminPhone'),
            "lastUpdatedDate": get_xml_text(krdomain, 'lastUpdatedDate'),
            "regDate": get_xml_text(krdomain, 'regDate'),
            "endDate": get_xml_text(krdomain, 'endDate'),
            "infoYN": get_xml_text(krdomain, 'infoYN'),
            "domainStatus": [e.text for e in krdomain.findall('domainStatus')],
            "agency": get_xml_text(krdomain, 'agency'),
            "agency_url": get_xml_text(krdomain, 'agency_url'),
            "e_regName": get_xml_text(krdomain, 'e_regName'),
            "e_addr": get_xml_text(krdomain, 'e_addr'),
            "e_adminName": get_xml_text(krdomain, 'e_adminName'),
            "e_agency": get_xml_text(krdomain, 'e_agency'),
            "dnssec": get_xml_text(krdomain, 'dnssec'),
            "ns1": [e.text for e in krdomain.findall('ns1')],
            "ip1": [e.text for e in krdomain.findall('ip1')],
        }
        
        return whois_data
        
    except ET.ParseError as e:
        return {
            "error": f"XML 파싱 오류: {str(e)}",
            "query": query
        }

def parse_ip_whois_xml(xml_content: str, query: str) -> dict:
    """
    IP용 whois API XML 응답 파싱
    """
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_content)
        whois_elem = root.find('./whois')
        if whois_elem is None:
            return {"error": "whois 태그를 찾을 수 없습니다.", "query": query}

        result = {
            "query": whois_elem.findtext('query'),
            "queryType": whois_elem.findtext('queryType'),
            "registry": whois_elem.findtext('registry'),
            "countryCode": whois_elem.findtext('countryCode'),
        }

        # 한글 ISP
        for child in whois_elem.findall('./korean/ISP/netInfo/*'):
            result[f"korean_ISP_{child.tag}"] = child.text
        for child in whois_elem.findall('./korean/ISP/techContact/*'):
            result[f"korean_ISP_contact_{child.tag}"] = child.text

        # 한글 user
        for child in whois_elem.findall('./korean/user/netInfo/*'):
            result[f"korean_user_{child.tag}"] = child.text
        for child in whois_elem.findall('./korean/user/techContact/*'):
            result[f"korean_user_contact_{child.tag}"] = child.text

        # 영문 ISP
        for child in whois_elem.findall('./english/ISP/netInfo/*'):
            result[f"english_ISP_{child.tag}"] = child.text
        for child in whois_elem.findall('./english/ISP/techContact/*'):
            result[f"english_ISP_contact_{child.tag}"] = child.text

        # 영문 user
        for child in whois_elem.findall('./english/user/netInfo/*'):
            result[f"english_user_{child.tag}"] = child.text
        for child in whois_elem.findall('./english/user/techContact/*'):
            result[f"english_user_contact_{child.tag}"] = child.text

        return result
    except ET.ParseError as e:
        return {"error": f"XML 파싱 오류: {str(e)}", "query": query}

@mcp.tool()
async def save_results_to_csv(results: List[Dict[str, Any]], output_file: str) -> Dict[str, Any]:
    """
    분석 결과를 CSV 파일로 저장합니다.
    
    Args:
        results: 저장할 결과 데이터
        output_file: 저장할 파일 경로
    
    Returns:
        저장 결과
    """
    try:
        if not results:
            return {
                "status": "error",
                "error": "저장할 데이터가 없습니다."
            }
        
        # CSV 헤더 생성
        headers = set()
        for result in results:
            if result.get("status") == "success" and "data" in result:
                headers.update(result["data"].keys())
        
        headers = ["query", "status", "query_time"] + sorted(list(headers))
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            
            for result in results:
                row = {
                    "query": result.get("query"),
                    "status": result.get("status"),
                    "query_time": result.get("query_time")
                }
                
                if result.get("status") == "success" and "data" in result:
                    row.update(result["data"])
                elif result.get("status") == "error":
                    row["error"] = result.get("error")
                
                writer.writerow(row)
        
        return {
            "status": "success",
            "file_path": output_file,
            "records_saved": len(results),
            "message": f"{len(results)}개 결과를 {output_file}에 저장했습니다."
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": f"CSV 저장 중 오류: {str(e)}"
        }

@mcp.tool()
async def save_results_to_txt(results: List[Dict[str, Any]], output_file: str, format_type: str = "simple") -> Dict[str, Any]:
    """
    분석 결과를 TXT 파일로 저장합니다.
    
    Args:
        results: 저장할 결과 데이터
        output_file: 저장할 파일 경로
        format_type: 형식 (simple/detailed)
    
    Returns:
        저장 결과
    """
    try:
        if not results:
            return {
                "status": "error",
                "error": "저장할 데이터가 없습니다."
            }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# Whois 분석 결과\n")
            f.write(f"# 생성일시: {datetime.now().isoformat()}\n")
            f.write(f"# 총 {len(results)}개 결과\n\n")
            
            for result in results:
                query = result.get("query")
                status = result.get("status")
                
                if format_type == "simple":
                    f.write(f"{query}\t{status}\n")
                else:  # detailed
                    f.write(f"=== {query} ===\n")
                    f.write(f"상태: {status}\n")
                    
                    if status == "success" and "data" in result:
                        data = result["data"]
                        for key, value in data.items():
                            if value:
                                f.write(f"{key}: {value}\n")
                    elif status == "error":
                        f.write(f"오류: {result.get('error')}\n")
                    
                    f.write("\n")
        
        return {
            "status": "success",
            "file_path": output_file,
            "records_saved": len(results),
            "format": format_type,
            "message": f"{len(results)}개 결과를 {output_file}에 저장했습니다."
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": f"TXT 저장 중 오류: {str(e)}"
        }

def get_xml_text(root, tag_name: str) -> Optional[str]:
    """XML에서 태그 텍스트를 안전하게 추출"""
    element = root.find(tag_name)
    return element.text if element is not None else None

def is_ip_address(value: str) -> bool:
    """입력값이 IPv4 또는 IPv6 주소인지 판별"""
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def main():
    print("Whois Analysis MCP Server 시작")
    mcp.run()

if __name__ == "__main__":
    main()