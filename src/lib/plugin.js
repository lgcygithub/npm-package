import Weblgcy from 'index';
import utils from 'utils';
import semver from 'semver';

export default class Plugin {

    constructor(weblgcy = false) {
        if (!weblgcy || !weblgcy instanceof Weblgcy)
            throw new Error('Expected instance of Weblgcy');
        this.weblgcy = weblgcy;
        this.pluginNoOverride = ['register'];
    }

    register(Plugin) {
        let pluginInterface = {
            requires: '0.0.0',
            components: {}
        }
        let result = {
            plugged: [],
            skipped: []
        }
        const plugin = new Plugin(this.weblgcy)
        if (utils.isFunction(plugin.pluginInterface)) {
            pluginInterface = plugin.pluginInterface()
        }
        if (semver.satisfies(Weblgcy.version, pluginInterface.requires)) {
            for (let component in pluginInterface.components) {
                if (!this.weblgcy.hasOwnProperty(component)) {
                    // TODO implement new sub-classes
                    continue
                }
                let methods = pluginInterface.components[component]
                let pluginNoOverride = this.weblgcy[component].pluginNoOverride || []
                for (let method in methods) {
                    if (method === 'constructor' || (this.weblgcy[component][method] &&
                        (pluginNoOverride.includes(method) // blacklisted methods
                            || /^_/.test(method)) // private methods
                    )) {
                        result.skipped.push(method)
                        continue
                    }
                    this.weblgcy[component][method] = methods[method].bind(this.weblgcy[component])
                    result.plugged.push(method)
                }
            }
        } else {
            throw new Error('The plugin is not compatible with this version of Weblgcy')
        }
        return result
    }
}

