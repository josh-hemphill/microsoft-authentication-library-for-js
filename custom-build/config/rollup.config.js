import ts from '@wessberg/rollup-plugin-ts';
const dist = './dist/';
import inject from '@rollup/plugin-inject';
/* const input = 'src/lib/index.ts'; */

export default [{
	input: '../lib/msal-node/src/index.ts',
	plugins:[
		ts({
			transpiler: 'babel',
			include: [
				'../lib/msal-common/src/**/*.[tj]s',
				'../lib/msal-node/src/**/*.[tj]s',
			],
			browserslist: false,
			tsconfig: '../tsconfig.json',
		}),
		inject({
			Buffer: ['buffer', 'Buffer'],
			process: ['process', 'process'],
		}),
	],
	output: [
		{
			file: `${dist}index.js`,
			exports: 'auto',
			format:'es',
			sourcemap: true,
		},
	],
}];
