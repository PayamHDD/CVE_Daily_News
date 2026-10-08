import re
import asyncio
import aiohttp
import logging
from bs4 import BeautifulSoup as bs

logger = logging.getLogger("TeleBot.Tenable")
class Version:
    pass

class CVE:
    def __init__(self, timeout = 5):
        self.timeout = timeout


    async def _info_parser(self, data):
        try:
            soup = bs(data, 'html.parser')
            links = soup.find_all("a")
            print(links)
        except:
            pass

    async def _cpe_parser(self, text):
        cpes = []
        soup = bs(text, 'html.parser')
        links = soup.find_all(href=re.compile("https://nvd.nist.gov/products/cpe\.*"))
        for item in links:
            cpes.append(item.string)
        return cpes

    async def _plugin_parser(self, data):
        plugins = []
        soup = bs(data, 'html.parser')
        links = soup.find_all(href=re.compile(r"(https://www.tenable.com/plugins/\w+/)(\d+)"))
        for item in links:
            plugins.append(item.string)
        return plugins


    async def _fetch(self, url):
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.get(url) as resp:
                    #resp.raise_for_status()
                    if resp.status != 200:
                        logger.error("Error fetching data - Tenable _fetch function")
                        #print(f"Error fetching data - Tenable _fetch function")
                        return None #Should be logged but don't know how!
                    else:
                        return await resp.text()
        except aiohttp.ClientError as err:
            logger.error("Error fetching data - Tenable _fetch function: %s", err)
            #print(f"Error fetching data: {e}") #Should be logged but don't know how!
            return None


    async def fetch_cve(self, cve_id):
        url = f"https://www.tenable.com/cve/{cve_id}"
        data = await self._fetch(url)
        if data:
            info = await self._info_parser(data)
        else:
            return None


    async def fetch_cve_plugin(self, cve_id):
        url = f"https://www.tenable.com/cve/{cve_id}/plugins"
        data = await self._fetch(url)
        if data:
            plugins = await self._plugin_parser(data)
            return plugins
        else:
            return None

    async def fetch_cve_cpe(self, cve_id):
        url = f"https://www.tenable.com/cve/{cve_id}/cpes"
        data = await self._fetch(url)
        if data:
            cpes = await self._cpe_parser(data)
            return cpes
        else:
            return None

