// This function represents breakpoints
// Copyright (c) 2019 Robert Bosch GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
export default function Breakpoints({ breakpoints }) {
  return (
    <div className="px-2">
      <div className="py-5 text-4xl font-extrabold text-gray-800 text-center">
        Breakpoints
      </div>
      <div className="space-y-2">
        {breakpoints.map((bp_address) => (
          <div className="text-xl text-gray-800" key={bp_address}>
              {"Address: 0x" +
              bp_address.toString(16).toUpperCase()}
          </div>
        ))}
      </div>
    </div>
  );
}
