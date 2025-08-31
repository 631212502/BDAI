from lxml import etree


class ScdParser:
    def __init__(self, scd_file):
        self.scd_file = scd_file
        self.tree = etree.parse(scd_file)
        self.ns = {'scl': 'http://www.iec.ch/61850/2003/SCL'}

    def get_goose_connections(self):
        """从SCD文件提取GOOSE连接关系"""
        connections = []

        # 提取所有GOOSE控制块
        goose_controls = self.tree.xpath('//scl:GSEControl', namespaces=self.ns)
        for control in goose_controls:
            control_ref = control.get('name')
            app_id = control.get('appID')
            dat_set = control.get('datSet')

            # 查找订阅此GOOSE的IED
            subscribers = self.tree.xpath(
                f'//scl:Inputs/scl:ExtRef[@intAddr="{control_ref}"]/ancestor::scl:IED',
                namespaces=self.ns
            )

            for sub in subscribers:
                sub_name = sub.get('name')
                connections.append({
                    'publisher': control.get('parent').get('name'),
                    'subscriber': sub_name,
                    'control_ref': control_ref,
                    'app_id': app_id,
                    'dataset': dat_set
                })

        return connections

    def validate_goose_links(self, live_connections):
        """验证实际链路与SCD配置是否一致"""
        scd_connections = self.get_goose_connections()
        issues = []

        # 检查配置中有但实际不存在的链路
        for scd_conn in scd_connections:
            found = False
            for live_conn in live_connections:
                if (scd_conn['publisher'] == live_conn['publisher'] and
                        scd_conn['subscriber'] == live_conn['subscriber'] and
                        scd_conn['app_id'] == live_conn['app_id']):
                    found = True
                    break

            if not found:
                issues.append({
                    'type': 'missing',
                    'connection': scd_conn
                })

        # 检查实际存在但未配置的链路
        for live_conn in live_connections:
            found = False
            for scd_conn in scd_connections:
                if (scd_conn['publisher'] == live_conn['publisher'] and
                        scd_conn['subscriber'] == live_conn['subscriber'] and
                        scd_conn['app_id'] == live_conn['app_id']):
                    found = True
                    break

            if not found:
                issues.append({
                    'type': 'unexpected',
                    'connection': live_conn
                })

        return issues