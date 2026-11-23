import { Studio } from '../components/studio';
import { rules } from '../engine/rules';
export default function Page() {
  return <Studio rules={rules}/>;
}
